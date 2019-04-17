#ifndef JSONTREEMODEL_H
#define JSONTREEMODEL_H

#include <QAbstractTableModel>
#include <QModelIndex>
#include <QVariant>
#include <QVariantList>
#include <QStringList>

class VariantMapModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    VariantMapModel(QObject *parent = 0);
    ~VariantMapModel();

    void setHeaders(const QStringList& headers);
    void setDataAndHeaders(const QVariantList& data);
    void setData(const QVariantList& data);
    void appendRow(const QVariantMap& row);
    QVariantList data() const;

    QVariant data(const QModelIndex &index, int role) const;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const;

    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    Qt::ItemFlags flags(const QModelIndex &index) const;

private:

    QStringList m_headers;
    QVariantList m_data;
};

#endif
