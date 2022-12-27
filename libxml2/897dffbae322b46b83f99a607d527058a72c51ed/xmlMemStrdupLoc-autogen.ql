/**
 * @name libxml2-897dffbae322b46b83f99a607d527058a72c51ed-xmlMemStrdupLoc
 * @id cpp/libxml2/897dffbae322b46b83f99a607d527058a72c51ed/xmlMemStrdupLoc
 * @description libxml2-897dffbae322b46b83f99a607d527058a72c51ed-xmlMemStrdupLoc CVE-2017-5130
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsize_496, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_496
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="18446744073709551575"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__xmlGenericError")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(0).(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__xmlGenericErrorContext")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(1).(StringLiteral).getValue()="xmlMallocLoc : Unsigned overflow\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlMemoryDump")
		and target_0.getThen().(BlockStmt).getStmt(2) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_3(Function func) {
	exists(ReturnStmt target_3 |
		target_3.getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_3))
}

from Function func, Variable vsize_496
where
not func_0(vsize_496, func)
and not func_3(func)
and vsize_496.getType().hasName("size_t")
and vsize_496.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
