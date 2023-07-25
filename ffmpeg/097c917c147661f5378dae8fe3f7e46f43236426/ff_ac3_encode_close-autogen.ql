/**
 * @name ffmpeg-097c917c147661f5378dae8fe3f7e46f43236426-ff_ac3_encode_close
 * @id cpp/ffmpeg/097c917c147661f5378dae8fe3f7e46f43236426/ff-ac3-encode-close
 * @description ffmpeg-097c917c147661f5378dae8fe3f7e46f43236426-libavcodec/ac3enc.c-ff_ac3_encode_close CVE-2020-22046
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_2020, AddressOfExpr target_2, ExprStmt target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="mdct_end"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2020
		and target_0.getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_0)
		and target_2.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_2020, Function func, ExprStmt target_1) {
		target_1.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="mdct_end"
		and target_1.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2020
		and target_1.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vs_2020
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Variable vs_2020, AddressOfExpr target_2) {
		target_2.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="blocks"
		and target_2.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2020
}

from Function func, Variable vs_2020, ExprStmt target_1, AddressOfExpr target_2
where
not func_0(vs_2020, target_2, target_1, func)
and func_1(vs_2020, func, target_1)
and func_2(vs_2020, target_2)
and vs_2020.getType().hasName("AC3EncodeContext *")
and vs_2020.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
