/**
 * @name libtiff-ae9365db1b271b62b35ce018eac8799b1d5e8a53-readContigTilesIntoBuffer
 * @id cpp/libtiff/ae9365db1b271b62b35ce018eac8799b1d5e8a53/readContigTilesIntoBuffer
 * @description libtiff-ae9365db1b271b62b35ce018eac8799b1d5e8a53-tools/tiffcrop.c-readContigTilesIntoBuffer CVE-2016-9539
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtile_buffsize_783, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vtile_buffsize_783
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294967292"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="readContigTilesIntoBuffer"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Integer overflow when calculating buffer size."
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_0))
}

predicate func_1(Variable vtile_buffsize_783, EqualityOperation target_6, ExprStmt target_7) {
	exists(AddExpr target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vtile_buffsize_783
		and target_1.getAnOperand().(Literal).getValue()="3"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFmalloc")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtile_buffsize_783
		and target_6.getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vtile_buffsize_783, Variable vtilebuf_785, ExprStmt target_7, EqualityOperation target_8, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vtilebuf_785
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtile_buffsize_783
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(26)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(26).getFollowingStmt()=target_2)
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_8.getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_3(Variable vtile_buffsize_783, Variable vtilebuf_785, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vtilebuf_785
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtile_buffsize_783
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(27)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(27).getFollowingStmt()=target_3))
}

predicate func_4(Variable vtile_buffsize_783, Variable vtilebuf_785, ExprStmt target_9, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vtilebuf_785
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtile_buffsize_783
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(28)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(28).getFollowingStmt()=target_4)
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_5(Variable vtile_buffsize_783, VariableAccess target_5) {
		target_5.getTarget()=vtile_buffsize_783
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFmalloc")
}

predicate func_6(Variable vtile_buffsize_783, EqualityOperation target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_6.getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vtile_buffsize_783
		and target_6.getAnOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("uint32")
}

predicate func_7(Variable vtile_buffsize_783, Variable vtilebuf_785, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtilebuf_785
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFmalloc")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtile_buffsize_783
}

predicate func_8(Variable vtilebuf_785, EqualityOperation target_8) {
		target_8.getAnOperand().(VariableAccess).getTarget()=vtilebuf_785
		and target_8.getAnOperand().(Literal).getValue()="0"
}

predicate func_9(Variable vtilebuf_785, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("tsize_t")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFReadTile")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("TIFF *")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtilebuf_785
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("uint32")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("uint32")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
}

from Function func, Variable vtile_buffsize_783, Variable vtilebuf_785, VariableAccess target_5, EqualityOperation target_6, ExprStmt target_7, EqualityOperation target_8, ExprStmt target_9
where
not func_0(vtile_buffsize_783, func)
and not func_1(vtile_buffsize_783, target_6, target_7)
and not func_2(vtile_buffsize_783, vtilebuf_785, target_7, target_8, func)
and not func_3(vtile_buffsize_783, vtilebuf_785, func)
and not func_4(vtile_buffsize_783, vtilebuf_785, target_9, func)
and func_5(vtile_buffsize_783, target_5)
and func_6(vtile_buffsize_783, target_6)
and func_7(vtile_buffsize_783, vtilebuf_785, target_7)
and func_8(vtilebuf_785, target_8)
and func_9(vtilebuf_785, target_9)
and vtile_buffsize_783.getType().hasName("tsize_t")
and vtilebuf_785.getType().hasName("unsigned char *")
and vtile_buffsize_783.(LocalVariable).getFunction() = func
and vtilebuf_785.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
