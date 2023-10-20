/**
 * @name libxml2-897dffbae322b46b83f99a607d527058a72c51ed-xmlReallocLoc
 * @id cpp/libxml2/897dffbae322b46b83f99a607d527058a72c51ed/xmlReallocLoc
 * @description libxml2-897dffbae322b46b83f99a607d527058a72c51ed-xmlReallocLoc CVE-2017-5130
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsize_322, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_322
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="18446744073709551575"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__xmlGenericError")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(0).(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__xmlGenericErrorContext")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(1).(StringLiteral).getValue()="xmlMallocLoc : Unsigned overflow\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlMemoryDump")
		and target_0.getThen().(BlockStmt).getStmt(2) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0))
}

predicate func_3(Function func) {
	exists(ReturnStmt target_3 |
		target_3.getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(31)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(31).getFollowingStmt()=target_3))
}

predicate func_5(Parameter vsize_322, Parameter vfile_322, Parameter vline_322) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("xmlMallocLoc")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vsize_322
		and target_5.getArgument(1).(VariableAccess).getTarget()=vfile_322
		and target_5.getArgument(2).(VariableAccess).getTarget()=vline_322)
}

from Function func, Parameter vsize_322, Parameter vfile_322, Parameter vline_322
where
not func_0(vsize_322, func)
and not func_3(func)
and vsize_322.getType().hasName("size_t")
and func_5(vsize_322, vfile_322, vline_322)
and vfile_322.getType().hasName("const char *")
and vline_322.getType().hasName("int")
and vsize_322.getParentScope+() = func
and vfile_322.getParentScope+() = func
and vline_322.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
