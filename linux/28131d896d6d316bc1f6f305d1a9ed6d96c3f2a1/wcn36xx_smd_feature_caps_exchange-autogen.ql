/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-wcn36xx_smd_feature_caps_exchange
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/wcn36xx-smd-feature-caps-exchange
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-wcn36xx_smd_feature_caps_exchange CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmsg_body_2390, Parameter vwcn_2388) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("set_feat_caps")
		and target_0.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="feat_caps"
		and target_0.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmsg_body_2390
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="rf_id"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_2388
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="13952")
}

predicate func_1(Variable vmsg_body_2390, Parameter vwcn_2388) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("set_feat_caps")
		and target_1.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="feat_caps"
		and target_1.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmsg_body_2390
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="rf_id"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_2388
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="13952")
}

predicate func_2(Variable vmsg_body_2390, Parameter vwcn_2388) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("set_feat_caps")
		and target_2.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="feat_caps"
		and target_2.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmsg_body_2390
		and target_2.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="rf_id"
		and target_2.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwcn_2388
		and target_2.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="13952")
}

from Function func, Variable vmsg_body_2390, Parameter vwcn_2388
where
not func_0(vmsg_body_2390, vwcn_2388)
and not func_1(vmsg_body_2390, vwcn_2388)
and func_2(vmsg_body_2390, vwcn_2388)
and vmsg_body_2390.getType().hasName("wcn36xx_hal_feat_caps_msg")
and vwcn_2388.getType().hasName("wcn36xx *")
and vmsg_body_2390.getParentScope+() = func
and vwcn_2388.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
