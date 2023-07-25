/**
 * @name yara-83d799804648c2a0895d40a19835d9b757c6fa4e-yr_re_fast_exec
 * @id cpp/yara/83d799804648c2a0895d40a19835d9b757c6fa4e/yr-re-fast-exec
 * @description yara-83d799804648c2a0895d40a19835d9b757c6fa4e-libyara/re.c-yr_re_fast_exec CVE-2017-8294
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinput_size_2167, VariableAccess target_0) {
		target_0.getTarget()=vinput_size_2167
}

predicate func_1(Parameter vflags_2168, Variable vmax_bytes_matched_2190, ExprStmt target_3, RelationalOperation target_4, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmax_bytes_matched_2190
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_2168
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getType().hasName("size_t")
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(VariableAccess).getType().hasName("size_t")
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_1)
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vinput_size_2167, Initializer target_2) {
		target_2.getExpr().(VariableAccess).getTarget()=vinput_size_2167
}

predicate func_3(Parameter vflags_2168, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_2168
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4"
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(UnaryMinusExpr).getValue()="-1"
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="1"
}

predicate func_4(Variable vmax_bytes_matched_2190, RelationalOperation target_4) {
		 (target_4 instanceof GEExpr or target_4 instanceof LEExpr)
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vmax_bytes_matched_2190
}

from Function func, Parameter vinput_size_2167, Parameter vflags_2168, Variable vmax_bytes_matched_2190, VariableAccess target_0, Initializer target_2, ExprStmt target_3, RelationalOperation target_4
where
func_0(vinput_size_2167, target_0)
and not func_1(vflags_2168, vmax_bytes_matched_2190, target_3, target_4, func)
and func_2(vinput_size_2167, target_2)
and func_3(vflags_2168, target_3)
and func_4(vmax_bytes_matched_2190, target_4)
and vinput_size_2167.getType().hasName("size_t")
and vflags_2168.getType().hasName("int")
and vmax_bytes_matched_2190.getType().hasName("int")
and vinput_size_2167.getParentScope+() = func
and vflags_2168.getParentScope+() = func
and vmax_bytes_matched_2190.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
