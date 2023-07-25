/**
 * @name freerdp-6b485b146a1b9d6ce72dfd7b5f36456c166e7a16-nego_read_request
 * @id cpp/freerdp/6b485b146a1b9d6ce72dfd7b5f36456c166e7a16/nego-read-request
 * @description freerdp-6b485b146a1b9d6ce72dfd7b5f36456c166e7a16-libfreerdp/core/nego.c-nego_read_request CVE-2020-11089
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(RelationalOperation target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand() instanceof FunctionCall
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vs_763, Parameter vnego_763, FunctionCall target_1) {
		target_1.getTarget().hasName("nego_process_negotiation_request")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vnego_763
		and target_1.getArgument(1).(VariableAccess).getTarget()=vs_763
}

predicate func_2(RelationalOperation target_3, Function func, ExprStmt target_2) {
		target_2.getExpr() instanceof FunctionCall
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Parameter vs_763, RelationalOperation target_3) {
		 (target_3 instanceof GEExpr or target_3 instanceof LEExpr)
		and target_3.getGreaterOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_3.getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_763
		and target_3.getLesserOperand().(Literal).getValue()="8"
}

from Function func, Parameter vs_763, Parameter vnego_763, FunctionCall target_1, ExprStmt target_2, RelationalOperation target_3
where
not func_0(target_3, func)
and func_1(vs_763, vnego_763, target_1)
and func_2(target_3, func, target_2)
and func_3(vs_763, target_3)
and vs_763.getType().hasName("wStream *")
and vnego_763.getType().hasName("rdpNego *")
and vs_763.getParentScope+() = func
and vnego_763.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
