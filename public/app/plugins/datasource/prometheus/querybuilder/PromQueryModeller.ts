import { getAggregationOperations } from './aggregations';
import { getOperationDefintions } from './operations';
import { LokiAndPromQueryModellerBase } from './shared/LokiAndPromQueryModellerBase';
import { PromQueryPattern, PromVisualQuery, PromVisualQueryOperationCategory } from './types';

export class PromQueryModeller extends LokiAndPromQueryModellerBase<PromVisualQuery> {
  constructor() {
    super();
    this.registerOperations(getOperationDefintions());
    this.registerOperations(getAggregationOperations());
    this.setOperationCategories([
      PromVisualQueryOperationCategory.Aggregations,
      PromVisualQueryOperationCategory.RateAndDeltas,
      PromVisualQueryOperationCategory.Functions,
      PromVisualQueryOperationCategory.Math,
    ]);
  }
  renderQuery(query: PromVisualQuery) {
    let queryString = `${query.metric}${this.renderLabels(query.labels)}`;
    queryString = this.renderOperations(queryString, query.operations);
    queryString = this.renderBinaryQueries(queryString, query.binaryQueries);
    return queryString;
  }

  getQueryPatterns(): PromQueryPattern[] {
    return [
      {
        name: 'Rate then sum',
        operations: [{ id: 'rate', params: ['auto'] }],
      },
      {
        name: 'Rate then sum by(label) then avg',
        operations: [
          { id: 'rate', params: ['auto'] },
          { id: '__sum_by', params: [''] },
          { id: 'avg', params: [] },
        ],
      },
      {
        name: 'Histogram quantile on rate',
        operations: [
          { id: 'rate', params: ['auto'] },
          { id: '__sum_by', params: ['le'] },
          { id: 'histogram_quantile', params: [0.95] },
        ],
      },
    ];
  }
}

export const promQueryModeller = new PromQueryModeller();
