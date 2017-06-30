import QtQuick 2.0

Rectangle {
    width: 300; height: 300
    color: "red"

    Text {
        id: helloText
        anchors.verticalCenter: parent.verticalCenter
        anchors.horizontalCenter: parent.horizontalCenter
        text: "Hello World!!!\n Traditional first app using PyQt5"
        color: "blue"
        font.family: "Helvetica"
        font.pointSize: 14
        horizontalAlignment: Text.AlignHCenter
    }

    Grid {
        id: colorPicker

        rows: 2; columns: 3; spacing: 3

        Cell { cellColor: "white"; onClicked: helloText.color = cellColor }
        Cell { cellColor: "green"; onClicked: helloText.color = cellColor }
        Cell { x: 100; cellColor: "blue"; onClicked: helloText.color = cellColor }
        Cell { cellColor: "yellow"; onClicked: helloText.color = cellColor }
        Cell { cellColor: "steelblue"; onClicked: helloText.color = cellColor }
        Cell { cellColor: "#ffffaa"; onClicked: helloText.color = cellColor }
    }

}
