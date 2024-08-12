import sys
import re
import webbrowser
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget, QAction, QMessageBox, \
    QProgressBar, QListWidget, QPushButton, QDialog, QFrame, QLineEdit
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from spotipy import Spotify, SpotifyOAuth
from spotipy.exceptions import SpotifyException

# Spotify API credentials
client_id = ''
client_secret = ''
redirect_uri = 'http://localhost:8888/callback'

# Scope for playlist read/write
scope = 'playlist-modify-public playlist-modify-private playlist-read-private'

# OAuth flow configuration
sp_oauth = SpotifyOAuth(client_id=client_id, client_secret=client_secret, redirect_uri=redirect_uri, scope=scope)
sp = None  # Placeholder for the Spotify client
selected_playlist_id = None  # To store the selected playlist ID


class DragDropFrame(QFrame):
    def __init__(self, parent=None, drop_handler=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.drop_handler = drop_handler
        self.setStyleSheet("background-color: lightgray; border: 2px dashed #a0a0a0;")

    def dragEnterEvent(self, event):
        print("Drag Enter Event Triggered")
        if event.mimeData().hasText():
            print("Accepting Text Data")
            event.acceptProposedAction()

    def dropEvent(self, event):
        print("Drop Event Triggered")
        url = event.mimeData().text().strip()
        print(f"URL Dropped: {url}")
        if self.drop_handler:
            self.drop_handler(url)


class SpotifyPlaylistHelper(QMainWindow):

    def __init__(self):
        super().__init__()
        self.playlists = None

        self.setWindowTitle("Spotify Playlist Helper")
        self.setGeometry(100, 100, 400, 300)

        menu_bar = self.menuBar()

        # Add Set Playlist and API Tokens options to the menu
        set_playlist_action = QAction("Set Playlist", self)
        set_playlist_action.triggered.connect(self.open_playlist_selection_window)
        menu_bar.addAction(set_playlist_action)

        api_tokens_action = QAction("API Tokens", self)
        api_tokens_action.triggered.connect(self.open_api_tokens_window)
        menu_bar.addAction(api_tokens_action)

        # Create a central widget and layout
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)

        layout = QVBoxLayout()

        # Drag-and-drop frame
        self.drag_frame = DragDropFrame(self, self.handle_dropped_url)
        self.drag_frame.setStyleSheet("background-color: lightgray; border: 2px dashed #a0a0a0;")
        self.drag_frame.setFixedHeight(200)
        self.drag_frame.setAcceptDrops(True)

        frame_layout = QVBoxLayout(self.drag_frame)
        frame_layout.setContentsMargins(0, 0, 0, 0)
        frame_layout.setSpacing(0)

        # Set the QLabel to match the drag frame's background and remove any borders
        self.drag_label = QLabel("Select a playlist to enable drag-and-drop functionality.", self.drag_frame)
        self.drag_label.setAlignment(Qt.AlignCenter)
        self.drag_label.setStyleSheet("background-color: transparent; border: none;")

        frame_layout.addWidget(self.drag_label)
        self.drag_frame.setLayout(frame_layout)

        layout.addWidget(self.drag_frame)
        self.drag_frame.setEnabled(False)

        self.central_widget.setLayout(layout)
        self.check_token_on_startup()

    def handle_dropped_url(self, url):
        spotify_url_pattern = r'https://open\.spotify\.com/track/(\w+)'
        spotify_uri_pattern = r'spotify:track:(\w+)'

        match = re.search(spotify_url_pattern, url) or re.search(spotify_uri_pattern, url)

        if match and selected_playlist_id:
            track_id = match.group(1)
            try:
                sp.playlist_add_items(selected_playlist_id, [f'spotify:track:{track_id}'])
                QMessageBox.information(self, "Success", f"Added track {track_id} to the playlist.")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to add track: {e}")
        else:
            QMessageBox.warning(self, "Invalid Data", "Please drop a valid Spotify track URL or URI.")

    def check_token_on_startup(self):
        try:
            global sp
            token_info = sp_oauth.get_cached_token()
            if not token_info:
                raise Exception("No valid token found.")
            sp = Spotify(auth=token_info['access_token'])
            print("Token fetched successfully on startup.")
        except Exception as e:
            print(f"Failed to fetch token on startup: {e}")
            self.open_api_tokens_window()

    def open_api_tokens_window(self):
        auth_url = sp_oauth.get_authorize_url()

        webbrowser.open(auth_url)
        QMessageBox.information(self, "Spotify OAuth", "Please authorize the app in your web browser.")

        try:
            token_info = sp_oauth.get_access_token(as_dict=False)
            if token_info:
                global sp
                sp = Spotify(auth=token_info)
                QMessageBox.information(self, "Authorization Success", "Spotify authorization successful.")
            else:
                raise Exception("Failed to retrieve access token.")
        except Exception as e:
            QMessageBox.warning(self, "Authorization Failed", f"Error during authorization: {e}")

    def open_playlist_selection_window(self):
        dialog = PlaylistSelectionDialog(self, self.playlists)
        if dialog.exec_() == QDialog.Accepted:
            self.playlists = dialog.playlists


class PlaylistSelectionDialog(QDialog):
    playlist_selected = pyqtSignal(str)

    def __init__(self, parent=None, playlists=None):
        super().__init__(parent)
        self.setWindowTitle("Select a Playlist")
        self.setGeometry(150, 150, 400, 400)

        self.layout = QVBoxLayout()

        # Search bar for filtering playlists
        self.search_bar = QLineEdit(self)
        self.search_bar.setPlaceholderText("Search Playlists...")
        self.layout.addWidget(self.search_bar)

        # Indeterminate progress bar
        self.progress_bar = QProgressBar(self)
        self.layout.addWidget(self.progress_bar)

        # List widget for playlists
        self.playlist_list_widget = QListWidget(self)
        self.layout.addWidget(self.playlist_list_widget)

        # Select button
        self.select_button = QPushButton("Select", self)
        self.select_button.clicked.connect(self.select_playlist)
        self.select_button.setEnabled(False)  # Initially disabled
        self.layout.addWidget(self.select_button)

        self.setLayout(self.layout)

        self.playlists = playlists if playlists is not None else []
        self.filtered_playlists = self.playlists

        if playlists is not None:
            self.on_playlists_fetched(playlists)
        else:
            # Start fetching playlists in a separate thread
            self.progress_bar.setRange(0, 0)  # Indeterminate mode
            self.fetch_playlists_thread = FetchPlaylistsThread()
            self.fetch_playlists_thread.playlists_fetched.connect(self.on_playlists_fetched)
            self.fetch_playlists_thread.error_occurred.connect(self.on_error_occurred)  # Handle errors
            self.fetch_playlists_thread.start()

        self.playlist_list_widget.itemSelectionChanged.connect(self.on_selection_changed)
        self.search_bar.textChanged.connect(self.filter_playlists)  # Connect search bar to filtering function

    def on_selection_changed(self):
        self.select_button.setEnabled(len(self.playlist_list_widget.selectedItems()) > 0)

    def on_playlists_fetched(self, playlists):
        self.progress_bar.setRange(0, 1)  # Stop indeterminate mode
        self.progress_bar.hide()

        self.playlists = playlists
        self.filtered_playlists = playlists
        self.populate_list_widget()

    def populate_list_widget(self):
        self.playlist_list_widget.clear()
        for playlist in self.filtered_playlists:
            self.playlist_list_widget.addItem(playlist['name'])

    def filter_playlists(self):
        search_text = self.search_bar.text().lower()
        self.filtered_playlists = [playlist for playlist in self.playlists if search_text in playlist['name'].lower()]
        self.populate_list_widget()

    def on_error_occurred(self, message):
        QMessageBox.warning(self, "Error", message)
        self.reject()

    def select_playlist(self):
        selected_items = self.playlist_list_widget.selectedItems()
        if selected_items:
            selected_playlist_name = selected_items[0].text()
            for playlist in self.playlists:
                if playlist['name'] == selected_playlist_name:
                    global selected_playlist_id
                    selected_playlist_id = playlist['id']
                    self.parent().drag_label.setText(f"Drag songs here to add to '{selected_playlist_name}'")
                    self.parent().drag_frame.setEnabled(True)
                    break
        self.accept()


class FetchPlaylistsThread(QThread):
    playlists_fetched = pyqtSignal(list)
    error_occurred = pyqtSignal(str)

    def run(self):
        playlists = []
        limit = 50
        offset = 0

        try:
            current_user = sp.current_user()
            user_id = current_user['id']

            while True:
                response = sp.current_user_playlists(limit=limit, offset=offset)
                user_playlists = [playlist for playlist in response['items'] if playlist['owner']['id'] == user_id]
                playlists.extend(user_playlists)
                offset += limit
                if len(response['items']) < limit:
                    break

            self.playlists_fetched.emit(playlists)

        except SpotifyException as e:
            if e.http_status == 401:
                self.error_occurred.emit("Authorization error: Token may have expired.")
            else:
                self.error_occurred.emit(f"An error occurred: {str(e)}")
        except Exception as e:
            self.error_occurred.emit(f"An unexpected error occurred: {str(e)}")


def main():
    app = QApplication(sys.argv)
    window = SpotifyPlaylistHelper()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
