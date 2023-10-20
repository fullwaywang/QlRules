/**
 * @name libtiff-cfbb883bf6ea7bedcb04177cc4e52d304522fdff-writeBufferToContigTiles
 * @id cpp/libtiff/cfbb883bf6ea7bedcb04177cc4e52d304522fdff/writeBufferToContigTiles
 * @description libtiff-cfbb883bf6ea7bedcb04177cc4e52d304522fdff-tools/tiffcrop.c-writeBufferToContigTiles CVE-2022-3598
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vtile_buffsize_1272, EqualityOperation target_4) {
	exists(AddExpr target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vtile_buffsize_1272
		and target_1.getAnOperand().(Literal).getValue()="3"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtile_buffsize_1272
		and target_4.getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vtile_buffsize_1272, Variable vtilebuf_1274, ExprStmt target_5, EqualityOperation target_6, RelationalOperation target_7, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtilebuf_1274
		and target_2.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_2.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtile_buffsize_1272
		and target_2.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="3"
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_2)
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_6.getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Variable vtile_buffsize_1272, VariableAccess target_3) {
		target_3.getTarget()=vtile_buffsize_1272
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
}

predicate func_4(Variable vtile_buffsize_1272, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_4.getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vtile_buffsize_1272
		and target_4.getAnOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_5(Variable vtile_buffsize_1272, Variable vtilebuf_1274, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtilebuf_1274
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("limitMalloc")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtile_buffsize_1272
}

predicate func_6(Variable vtilebuf_1274, EqualityOperation target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vtilebuf_1274
		and target_6.getAnOperand().(Literal).getValue()="0"
}

predicate func_7(Variable vtilebuf_1274, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getGreaterOperand().(FunctionCall).getTarget().hasName("extractContigSamplesToTileBuffer")
		and target_7.getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtilebuf_1274
		and target_7.getGreaterOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("uint8_t *")
		and target_7.getGreaterOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_7.getGreaterOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_7.getGreaterOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_7.getGreaterOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_7.getGreaterOperand().(FunctionCall).getArgument(6).(Literal).getValue()="0"
		and target_7.getGreaterOperand().(FunctionCall).getArgument(7).(VariableAccess).getTarget().getType().hasName("tsample_t")
		and target_7.getGreaterOperand().(FunctionCall).getArgument(8).(VariableAccess).getTarget().getType().hasName("tsample_t")
		and target_7.getGreaterOperand().(FunctionCall).getArgument(9).(VariableAccess).getTarget().getType().hasName("uint16_t")
		and target_7.getGreaterOperand().(FunctionCall).getArgument(10).(VariableAccess).getTarget().getType().hasName("dump_opts *")
		and target_7.getLesserOperand().(Literal).getValue()="0"
}

from Function func, Variable vtile_buffsize_1272, Variable vtilebuf_1274, VariableAccess target_3, EqualityOperation target_4, ExprStmt target_5, EqualityOperation target_6, RelationalOperation target_7
where
not func_1(vtile_buffsize_1272, target_4)
and not func_2(vtile_buffsize_1272, vtilebuf_1274, target_5, target_6, target_7, func)
and func_3(vtile_buffsize_1272, target_3)
and func_4(vtile_buffsize_1272, target_4)
and func_5(vtile_buffsize_1272, vtilebuf_1274, target_5)
and func_6(vtilebuf_1274, target_6)
and func_7(vtilebuf_1274, target_7)
and vtile_buffsize_1272.getType().hasName("tsize_t")
and vtilebuf_1274.getType().hasName("unsigned char *")
and vtile_buffsize_1272.(LocalVariable).getFunction() = func
and vtilebuf_1274.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
