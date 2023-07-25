/**
 * @name libwebp-be738c6d396fa5a272c1b209be4379a7532debfe-ChunkVerifyAndAssign
 * @id cpp/libwebp/be738c6d396fa5a272c1b209be4379a7532debfe/ChunkVerifyAndAssign
 * @description libwebp-be738c6d396fa5a272c1b209be4379a7532debfe-src/mux/muxread.c-ChunkVerifyAndAssign CVE-2020-36331
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vchunk_size_56, ExprStmt target_1, FunctionCall target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vchunk_size_56
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294967286"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vchunk_size_56, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchunk_size_56
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("GetLE32")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="4"
}

predicate func_2(Variable vchunk_size_56, FunctionCall target_2) {
		target_2.getTarget().hasName("SizeWithPadding")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vchunk_size_56
}

from Function func, Variable vchunk_size_56, ExprStmt target_1, FunctionCall target_2
where
not func_0(vchunk_size_56, target_1, target_2, func)
and func_1(vchunk_size_56, target_1)
and func_2(vchunk_size_56, target_2)
and vchunk_size_56.getType().hasName("uint32_t")
and vchunk_size_56.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
