/**
 * @name libarchive-e79ef306afe332faf22e9b442a2c6b59cb175573-read_SubStreamsInfo
 * @id cpp/libarchive/e79ef306afe332faf22e9b442a2c6b59cb175573/read-SubStreamsInfo
 * @description libarchive-e79ef306afe332faf22e9b442a2c6b59cb175573-libarchive/archive_read_support_format_7zip.c-read_SubStreamsInfo CVE-2016-4300
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vunpack_streams_2135, ExprStmt target_1, ExprStmt target_2) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vunpack_streams_2135
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="18446744073609551615"
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vunpack_streams_2135, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vunpack_streams_2135
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_2(Variable vunpack_streams_2135, ExprStmt target_2) {
		target_2.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vunpack_streams_2135
		and target_2.getExpr().(AssignAddExpr).getRValue().(ValueFieldAccess).getTarget().getName()="numUnpackStreams"
}

from Function func, Variable vunpack_streams_2135, ExprStmt target_1, ExprStmt target_2
where
not func_0(vunpack_streams_2135, target_1, target_2)
and func_1(vunpack_streams_2135, target_1)
and func_2(vunpack_streams_2135, target_2)
and vunpack_streams_2135.getType().hasName("size_t")
and vunpack_streams_2135.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
