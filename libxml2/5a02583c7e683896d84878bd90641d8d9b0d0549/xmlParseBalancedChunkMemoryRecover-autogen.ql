/**
 * @name libxml2-5a02583c7e683896d84878bd90641d8d9b0d0549-xmlParseBalancedChunkMemoryRecover
 * @id cpp/libxml2/5a02583c7e683896d84878bd90641d8d9b0d0549/xmlParseBalancedChunkMemoryRecover
 * @description libxml2-5a02583c7e683896d84878bd90641d8d9b0d0549-xmlParseBalancedChunkMemoryRecover CVE-2019-19956
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdoc_13764, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdoc_13764
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(39)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(39).getFollowingStmt()=target_0))
}

predicate func_1(Variable vnewDoc_13768, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="oldNs"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnewDoc_13768
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Parameter vdoc_13764, Variable vcur_13876) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("xmlSetTreeDoc")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vcur_13876
		and target_2.getArgument(1).(VariableAccess).getTarget()=vdoc_13764)
}

from Function func, Parameter vdoc_13764, Variable vnewDoc_13768, Variable vcur_13876
where
not func_0(vdoc_13764, func)
and func_1(vnewDoc_13768, func)
and vdoc_13764.getType().hasName("xmlDocPtr")
and func_2(vdoc_13764, vcur_13876)
and vnewDoc_13768.getType().hasName("xmlDocPtr")
and vcur_13876.getType().hasName("xmlNodePtr")
and vdoc_13764.getParentScope+() = func
and vnewDoc_13768.getParentScope+() = func
and vcur_13876.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
