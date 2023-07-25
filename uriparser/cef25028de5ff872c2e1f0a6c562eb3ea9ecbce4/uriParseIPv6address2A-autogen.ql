/**
 * @name uriparser-cef25028de5ff872c2e1f0a6c562eb3ea9ecbce4-uriParseIPv6address2A
 * @id cpp/uriparser/cef25028de5ff872c2e1f0a6c562eb3ea9ecbce4/uriParseIPv6address2A
 * @description uriparser-cef25028de5ff872c2e1f0a6c562eb3ea9ecbce4-src/UriParse.c-uriParseIPv6address2A CVE-2018-20721
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vfirst_578, Parameter vafterLast_578, Parameter vmemory_579, Parameter vstate_577, IfStmt target_1) {
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vfirst_578
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vafterLast_578
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("uriStopSyntaxA")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstate_577
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfirst_578
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vmemory_579
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

from Function func, Parameter vfirst_578, Parameter vafterLast_578, Parameter vmemory_579, Parameter vstate_577, IfStmt target_1
where
func_1(vfirst_578, vafterLast_578, vmemory_579, vstate_577, target_1)
and vfirst_578.getType().hasName("const char *")
and vafterLast_578.getType().hasName("const char *")
and vmemory_579.getType().hasName("UriMemoryManager *")
and vstate_577.getType().hasName("UriParserStateA *")
and vfirst_578.getParentScope+() = func
and vafterLast_578.getParentScope+() = func
and vmemory_579.getParentScope+() = func
and vstate_577.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
