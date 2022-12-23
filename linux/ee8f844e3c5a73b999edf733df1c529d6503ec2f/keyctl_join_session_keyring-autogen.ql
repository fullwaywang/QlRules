/**
 * @name linux-ee8f844e3c5a73b999edf733df1c529d6503ec2f-keyctl_join_session_keyring
 * @id cpp/linux/ee8f844e3c5a73b999edf733df1c529d6503ec2f/keyctl-join-session-keyring
 * @description linux-ee8f844e3c5a73b999edf733df1c529d6503ec2f-keyctl_join_session_keyring CVE-2016-9604
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter v_name_280, Variable vret_283) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_283
		and target_0.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
		and target_0.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=v_name_280)
}

predicate func_1(Parameter v_name_280, Variable vname_282) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vname_282
		and target_1.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="46"
		and target_1.getThen().(GotoStmt).toString() = "goto ..."
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=v_name_280)
}

predicate func_2(Function func) {
	exists(LabelStmt target_2 |
		target_2.toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_2))
}

predicate func_3(Variable vname_282) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("PTR_ERR")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vname_282)
}

from Function func, Parameter v_name_280, Variable vname_282, Variable vret_283
where
not func_0(v_name_280, vret_283)
and not func_1(v_name_280, vname_282)
and not func_2(func)
and v_name_280.getType().hasName("const char *")
and vname_282.getType().hasName("char *")
and func_3(vname_282)
and vret_283.getType().hasName("long")
and v_name_280.getParentScope+() = func
and vname_282.getParentScope+() = func
and vret_283.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
