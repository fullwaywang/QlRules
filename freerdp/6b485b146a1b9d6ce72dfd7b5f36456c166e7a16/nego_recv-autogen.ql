/**
 * @name freerdp-6b485b146a1b9d6ce72dfd7b5f36456c166e7a16-nego_recv
 * @id cpp/freerdp/6b485b146a1b9d6ce72dfd7b5f36456c166e7a16/nego-recv
 * @description freerdp-6b485b146a1b9d6ce72dfd7b5f36456c166e7a16-libfreerdp/core/nego.c-nego_recv CVE-2020-11089
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(VariableAccess target_6, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand() instanceof FunctionCall
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_6
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(VariableAccess target_6, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand() instanceof FunctionCall
		and target_1.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_6
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vs_600, Variable vnego_605, FunctionCall target_2) {
		target_2.getTarget().hasName("nego_process_negotiation_response")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vnego_605
		and target_2.getArgument(1).(VariableAccess).getTarget()=vs_600
}

predicate func_3(Parameter vs_600, Variable vnego_605, FunctionCall target_3) {
		target_3.getTarget().hasName("nego_process_negotiation_failure")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vnego_605
		and target_3.getArgument(1).(VariableAccess).getTarget()=vs_600
}

predicate func_4(VariableAccess target_6, Function func, ExprStmt target_4) {
		target_4.getExpr() instanceof FunctionCall
		and target_4.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_6
		and target_4.getEnclosingFunction() = func
}

predicate func_5(VariableAccess target_6, Function func, ExprStmt target_5) {
		target_5.getExpr() instanceof FunctionCall
		and target_5.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_6
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Variable vtype_603, VariableAccess target_6) {
		target_6.getTarget()=vtype_603
}

from Function func, Parameter vs_600, Variable vtype_603, Variable vnego_605, FunctionCall target_2, FunctionCall target_3, ExprStmt target_4, ExprStmt target_5, VariableAccess target_6
where
not func_0(target_6, func)
and not func_1(target_6, func)
and func_2(vs_600, vnego_605, target_2)
and func_3(vs_600, vnego_605, target_3)
and func_4(target_6, func, target_4)
and func_5(target_6, func, target_5)
and func_6(vtype_603, target_6)
and vs_600.getType().hasName("wStream *")
and vtype_603.getType().hasName("BYTE")
and vnego_605.getType().hasName("rdpNego *")
and vs_600.getParentScope+() = func
and vtype_603.getParentScope+() = func
and vnego_605.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
