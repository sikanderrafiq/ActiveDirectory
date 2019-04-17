#include "MenuColumnTableWidget.h"
#include <QLabel>
#include <QHBoxLayout>
#include <QMenu>
#include <QMetaMethod>
#include <QDebug>

#define MINIMUM_COLUMN_WIDTH 175
#define GEAR_COLUMN_WIDTH 50

MenuColumnTableWidget::MenuColumnTableWidget(QWidget *parent) :
    QTableWidget(parent),
    m_selectedRowIndex(-1),
    m_isGearHeaderColumnAdded(false),
    m_menu(nullptr),
    m_echoPasswordColumn(-1),
    m_isUniformColumnWidth(false),
    m_strechColumnIndex(-1)
{
    connect(this, SIGNAL(clicked(const QModelIndex&)), SLOT(onItemClicked(const QModelIndex&)));
}

void MenuColumnTableWidget::setColumnMappings(const QStringList& columnMappings)
{
    m_columnMappings = columnMappings;
}

/*
 * This column data will be shown as '******'
 */
void MenuColumnTableWidget::setEchoPasswordColumn(int column)
{
    if (column >= 0 && column < totalColumns()) {
        m_echoPasswordColumn = column;
    }
}

void MenuColumnTableWidget::setUniformColumnWidth(bool on)
{
    if (m_isUniformColumnWidth != on) {
        m_isUniformColumnWidth = on;
        resetColumnWidth();
    }
}

void MenuColumnTableWidget::setStrechColumn(int column)
{
    if (m_strechColumnIndex != column) {
        m_strechColumnIndex = column;
        resetColumnWidth();
    }
}

int MenuColumnTableWidget::appendRow()
{
    int rows = rowCount();
    setRowCount(rows + 1);
    if (m_isGearHeaderColumnAdded) {
        addGearColumnInNewRow(rows);
    }
    return rows; // new row index
}

/*
 * This function will return columns count without "Gear" column
 */
int MenuColumnTableWidget::totalColumns()
{
    return m_isGearHeaderColumnAdded ? columnCount() - 1 : columnCount();
}

/*
 * Set data to specified cell of QTableWidget. cell is identified by row and column.
 */
void MenuColumnTableWidget::setText(int row, int column, const QString& data)
{
    QTableWidgetItem *item = new QTableWidgetItem(data);
    item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
    setItem(row, column, item);
}

void MenuColumnTableWidget::resizeEvent(QResizeEvent *event)
{
    QTableWidget::resizeEvent(event);
    if (m_isUniformColumnWidth || m_strechColumnIndex != -1) {
        resetColumnWidth();
    }
}

/*
 * Reset column width according to width of the control.
 */
void MenuColumnTableWidget::resetColumnWidth()
{
    int columns = totalColumns();
    if (columns < 1 ) {
        return;
    }

    int availableWidth = m_isGearHeaderColumnAdded ? (width() - GEAR_COLUMN_WIDTH - 15) : (width() - 15);

    if (m_isUniformColumnWidth) {
        int columnWidth = availableWidth / columns;
        if (columnWidth < MINIMUM_COLUMN_WIDTH) {
            columnWidth = MINIMUM_COLUMN_WIDTH;
        }

        for (int i = 0; i < columns; i++) {
            setColumnWidth(i, columnWidth);
        }
    } else if (m_strechColumnIndex != -1 && m_strechColumnIndex < columns) {
        int otherColumnsTotalWidth = 0;
        for (int i = 0; i < columns; i++) {
            if (i == m_strechColumnIndex) {
                continue;
            }
            otherColumnsTotalWidth += columnWidth(i);
        }
        int stretchColumnWidth = availableWidth - otherColumnsTotalWidth;
        setColumnWidth(m_strechColumnIndex, stretchColumnWidth);
    }
}

void MenuColumnTableWidget::onItemClicked(const QModelIndex& index)
{
    if (index.isValid() && index.column() == (columnCount() - 1)) {
        m_selectedRowIndex = index.row();

        // current row selected
        selectRow(index.row());

        if (m_menu) {
            QPoint pt = QCursor::pos();
            pt.setX(pt.x() - m_menu->width());
            pt.setY(pt.y() - m_menu->height());
            m_menu->exec(pt);
        }
    }
}

/*
 * Set header for the additional column which only contains "gear" icon.
 */
void MenuColumnTableWidget::addGearHeaderColumn()
{
    if (!m_isGearHeaderColumnAdded) {
        int columns = columnCount();
        setColumnCount(columns + 1);
        setColumnWidth(columns, GEAR_COLUMN_WIDTH);

        // set column text
        QTableWidgetItem *item = new QTableWidgetItem("");
        item->setFlags(Qt::ItemIsEnabled);
        setHorizontalHeaderItem(columns, item);
        m_isGearHeaderColumnAdded = true;
    }
}

void MenuColumnTableWidget::setMenu(QMenu *menu)
{
    m_menu = menu;
}

QMenu *MenuColumnTableWidget::menu() const
{
    return m_menu;
}

/*
 * This function add "gear" column in each new row.
 */
void MenuColumnTableWidget::addGearColumnInNewRow(int row)
{
    // last column is considered as "gear" column
    int gearColumn = columnCount() - 1;
    setColumnWidth(gearColumn, GEAR_COLUMN_WIDTH);

    // set "gear" column not selectable. User can click on gear icon.
    QTableWidgetItem *item = new QTableWidgetItem("");
    item->setFlags(Qt::ItemIsEnabled);
    setItem(row, gearColumn, item);

    // now set gear icon
    addGearWidget(row);
}

/*
 * This internal functional sets gear icon in "gear" column
 */
void MenuColumnTableWidget::addGearWidget(int row)
{
    QPixmap image;
    QLabel *imageLabel = new QLabel();
    if (image.load(":gfx/toolbar-icons/normal/Settings-24.png")) {
        imageLabel->setFixedSize(image.size());
        imageLabel->setPixmap(image);

        // Create a widget that will contain a gear icon label widget
        QWidget *labelWidget = new QWidget(this);
        QHBoxLayout *horizontalLayout = new QHBoxLayout(labelWidget);
        horizontalLayout->addWidget(imageLabel);          // Add label in the horizontal layout
        horizontalLayout->setAlignment(Qt::AlignCenter);  // Center the label widget
        horizontalLayout->setContentsMargins(0,0,0,0);    // Set the zero padding

        int gearColumn = columnCount() - 1;
        setCellWidget(row, gearColumn, labelWidget);
    }
}

/*
 * Get data of QTableWidget row
 */
bool MenuColumnTableWidget::rowData(int row, QVariantMap *map)
{
    if (row < rowCount()) {
        for (int column = 0; column < totalColumns(); column++) {
            QString data = cellData(row, column);
            QString columnMapping = (column < m_columnMappings.size()) ? m_columnMappings[column] : QString::number(column);
            (*map)[columnMapping] = data;
        }
        return true;
    }
    return false;
}

/*
 * Return cell (identified by row and column) data
 *  row             row index
 *  column          column index
 */
QString MenuColumnTableWidget::cellData(int row, int column)
{
    QString data;
    if (row < rowCount() && column < totalColumns()) {
        QTableWidgetItem *cellItem = item(row, column);
        if (cellItem) {
            data = cellItem->text();
        }
    }
    return data;
}

/*
 * Get data in QVariantList. Each cell data is in QString format
 */
QVariantList MenuColumnTableWidget::data()
{
    QVariantList list;
    int rows = rowCount();
    for (int row = 0; row < rows; row++) {
        QVariantMap map;
        rowData(row, &map);
        list.append(map);
    }
    return list;
}

/*
 * Set QVariantList data back to the table. Each item data is in QString format
 */
void MenuColumnTableWidget::setData(const QVariantList& list)
{
    clearContents();
    setRowCount(0);

    int rows = list.size();
    for (int row = 0; row < rows; row++) {
        appendRow();
        QVariantMap map = list[row].toMap();
        for (int column = 0; column < totalColumns(); column++) {
            QString columnMapping = (column < m_columnMappings.size()) ? m_columnMappings[column] : QString::number(column);
            QString data = map[columnMapping].toString();
            setText(row, column, data);
        }
    }
}
