import { Action } from '@reduxjs/toolkit';

import { dispatch, getState } from 'app/store/store';
import { RuleGroupIdentifier } from 'app/types/unified-alerting';
import { PostableRulerRuleGroupDTO } from 'app/types/unified-alerting-dto';

import { alertRuleApi } from '../../api/alertRuleApi';
import { notFoundToNullOrThrow } from '../../api/util';
import { ruleGroupReducer } from '../../reducers/ruler/ruleGroups';
import { fetchRulesSourceBuildInfoAction, getDataSourceRulerConfig } from '../../state/actions';
import { DEFAULT_GROUP_EVALUATION_INTERVAL } from '../../utils/rule-form';

/**
 * Hook for reuse that handles freshly fetching a rule group's definition, applying an action to it,
 * and then performing the API mutations necessary to persist the change.
 *
 * All rule groups changes should ideally be implemented as a wrapper around this hook,
 * to ensure that we always protect as best we can against accidentally overwriting changes,
 * and to guard against user concurrency issues.
 *
 * @throws
 */
export function useProduceNewRuleGroup() {
  const [fetchRuleGroup, requestState] = alertRuleApi.endpoints.getRuleGroupForNamespace.useLazyQuery();

  /**
   * This function will fetch the latest configuration we have for the rule group, apply a diff to it via a reducer and sends
   * returns the result.
   *
   * The API does not allow operations on a single rule and will always overwrite the existing rule group with the payload.
   *
   * ┌─────────────────────────┐  ┌───────────────┐  ┌──────────────────┐
   * │ fetch latest rule group │─▶│ apply reducer │─▶│  new rule group  │
   * └─────────────────────────┘  └───────────────┘  └──────────────────┘
   */
  const produceNewRuleGroup = async (ruleGroup: RuleGroupIdentifier, action: Action) => {
    const { dataSourceName, groupName, namespaceName } = ruleGroup;

    // @TODO we should really not work with the redux state (getState) here
    await dispatch(fetchRulesSourceBuildInfoAction({ rulesSourceName: dataSourceName }));
    const rulerConfig = getDataSourceRulerConfig(getState, dataSourceName);

    const latestRuleGroupDefinition = await fetchRuleGroup({
      rulerConfig,
      namespace: namespaceName,
      group: groupName,
      // @TODO maybe only supress if 404?
      requestOptions: { showErrorAlert: false },
    })
      .unwrap()
      .catch(notFoundToNullOrThrow);

    const newRuleGroupDefinition = ruleGroupReducer(
      latestRuleGroupDefinition ?? createBlankRuleGroup(ruleGroup.groupName),
      action
    );

    return { newRuleGroupDefinition, rulerConfig };
  };

  return [produceNewRuleGroup, requestState] as const;
}

const createBlankRuleGroup = (name: string): PostableRulerRuleGroupDTO => ({
  name,
  interval: DEFAULT_GROUP_EVALUATION_INTERVAL,
  rules: [],
});
