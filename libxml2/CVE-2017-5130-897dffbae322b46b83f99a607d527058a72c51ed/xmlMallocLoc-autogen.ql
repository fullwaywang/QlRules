/**
 * @name libxml2-897dffbae322b46b83f99a607d527058a72c51ed-xmlMallocLoc
 * @id cpp/libxml2/897dffbae322b46b83f99a607d527058a72c51ed/xmlMallocLoc
 * @description libxml2-897dffbae322b46b83f99a607d527058a72c51ed-xmlMallocLoc CVE-2017-5130
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsize_162, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_162
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="18446744073709551575"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__xmlGenericError")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(0).(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__xmlGenericErrorContext")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(1).(StringLiteral).getValue()="xmlMallocLoc : Unsigned overflow\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlMemoryDump")
		and target_0.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0))
}

from Function func, Parameter vsize_162
where
not func_0(vsize_162, func)
and vsize_162.getType().hasName("size_t")
and vsize_162.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
