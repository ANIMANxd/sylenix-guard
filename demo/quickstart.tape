# Regenerate with:
#   make build
#   vhs demo/quickstart.tape
#
# The recording runs the real Guard against demo/fake_server.py. The approval
# prompt is rendered as terminal text for the recording; it is a wiring demo,
# not a model measurement.

Output demo/quickstart.gif

Set Width 1100
Set Height 720
Set Padding 24
Set FontSize 16
Set TypingSpeed 35ms
Set Framerate 30
Set CursorBlink false

Sleep 500ms
Type "go run ./demo/gifrunner"
Enter
Sleep 19.2s
