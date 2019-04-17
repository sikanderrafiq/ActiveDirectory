#ifndef MENUCOLUMNTABLEWIDGET_H
#define MENUCOLUMNTABLEWIDGET_H
#include <QTableWidget>

class QModelIndex;

/*
 * This class extends QTableWidget and add "gear" icon in its last column to provide facility
 * to the user to support different actions like edit, delete etc. on each of its row.
 */

class MenuColumnTableWidget : public QTableWidget
{
    Q_OBJECT
public:
    explicit MenuColumnTableWidget(QWidget *parent = nullptr);

    void addGearHeaderColumn();
    void setColumnMappings(const QStringList& columnMappings);

    int totalColumns();

    int appendRow();
    void setText(int row, int column, const QString& text);

    void setMenu(QMenu *menu);
    QMenu *menu() const;

    bool rowData(int row, QVariantMap *map);

    QVariantList data();
    void setData(const QVariantList& list);

    QString cellData(int row, int column);

    void setEchoPasswordColumn(int column);
    void setUniformColumnWidth(bool on);
    // Pass -1 to disable
    void setStrechColumn(int column);

protected:
    void resizeEvent(QResizeEvent *event) override;

private slots:
    void onItemClicked(const QModelIndex& index);

private:
    void addGearColumnInNewRow(int row);
    void addGearWidget(int row);
     void resetColumnWidth();

private:
    int m_selectedRowIndex;
    QStringList m_columnMappings;
    bool m_isGearHeaderColumnAdded;
    QMenu *m_menu;
    int m_echoPasswordColumn;
    bool m_isUniformColumnWidth;
    int m_strechColumnIndex;
};

#endif // MENUCOLUMNTABLEWIDGET_H
