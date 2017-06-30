import QtQuick 2.0

Item {
    id: container
    property alias cellColor: rectangle.color
    signal clicked(color cellColor)

    width: 40; height: 25

    Rectangle {
    id: rectangle
    width: 80
    border.color: "white"
    anchors.fill: parent
    }

    MouseArea {
        width: 80
        anchors.fill: parent
        onClicked: container.clicked(container.cellColor)
    }
}
