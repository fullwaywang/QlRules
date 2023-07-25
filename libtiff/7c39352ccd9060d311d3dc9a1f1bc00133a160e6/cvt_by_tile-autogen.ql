/**
 * @name libtiff-7c39352ccd9060d311d3dc9a1f1bc00133a160e6-cvt_by_tile
 * @id cpp/libtiff/7c39352ccd9060d311d3dc9a1f1bc00133a160e6/cvt-by-tile
 * @description libtiff-7c39352ccd9060d311d3dc9a1f1bc00133a160e6-tools/tiff2rgba.c-cvt_by_tile CVE-2016-3945
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getType().hasName("uint32")
		and target_0.getRValue() instanceof MulExpr
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vin_141, Variable vtile_width_146, Variable vtile_height_146, FunctionCall target_10, FunctionCall target_11, MulExpr target_8, MulExpr target_9, AssignAddExpr target_12, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtile_width_146
		and target_1.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(DivExpr).getLeftOperand().(VariableAccess).getType().hasName("uint32")
		and target_1.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vtile_height_146
		and target_1.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("TIFFFileName")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vin_141
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Integer overflow when calculating raster buffer"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_1)
		and target_10.getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getArgument(0).(VariableAccess).getLocation())
		and target_8.getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_9.getLeftOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(DivExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_12.getRValue().(VariableAccess).getLocation()))
}

predicate func_2(Variable vraster_144, EqualityOperation target_13, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vraster_144
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFmalloc")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("uint32")
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_2)
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_4(Function func) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(VariableAccess).getType().hasName("uint32")
		and target_4.getRValue() instanceof MulExpr
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Parameter vin_141, Variable vtile_width_146, FunctionCall target_11, FunctionCall target_14, MulExpr target_9, AssignAddExpr target_15, Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtile_width_146
		and target_5.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getType().hasName("uint32")
		and target_5.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_5.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("TIFFFileName")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vin_141
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Integer overflow when calculating wrk_line buffer"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit")
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_5)
		and target_11.getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_14.getArgument(0).(VariableAccess).getLocation())
		and target_9.getLeftOperand().(VariableAccess).getLocation().isBefore(target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_15.getRValue().(VariableAccess).getLocation()))
}

predicate func_6(Variable vwrk_line_148, NotExpr target_16, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vwrk_line_148
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFmalloc")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("uint32")
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_6)
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_16.getOperand().(VariableAccess).getLocation()))
}

predicate func_8(Variable vtile_width_146, Variable vtile_height_146, MulExpr target_8) {
		target_8.getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vtile_width_146
		and target_8.getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vtile_height_146
		and target_8.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_8.getRightOperand().(SizeofTypeOperator).getValue()="4"
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFmalloc")
}

predicate func_9(Variable vtile_width_146, MulExpr target_9) {
		target_9.getLeftOperand().(VariableAccess).getTarget()=vtile_width_146
		and target_9.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_9.getRightOperand().(SizeofTypeOperator).getValue()="4"
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFmalloc")
}

predicate func_10(Parameter vin_141, FunctionCall target_10) {
		target_10.getTarget().hasName("TIFFFileName")
		and target_10.getArgument(0).(VariableAccess).getTarget()=vin_141
}

predicate func_11(Parameter vin_141, FunctionCall target_11) {
		target_11.getTarget().hasName("TIFFFileName")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vin_141
}

predicate func_12(Variable vtile_height_146, AssignAddExpr target_12) {
		target_12.getLValue().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_12.getRValue().(VariableAccess).getTarget()=vtile_height_146
}

predicate func_13(Variable vraster_144, EqualityOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vraster_144
		and target_13.getAnOperand().(Literal).getValue()="0"
}

predicate func_14(Parameter vin_141, FunctionCall target_14) {
		target_14.getTarget().hasName("TIFFFileName")
		and target_14.getArgument(0).(VariableAccess).getTarget()=vin_141
}

predicate func_15(Variable vtile_width_146, AssignAddExpr target_15) {
		target_15.getLValue().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_15.getRValue().(VariableAccess).getTarget()=vtile_width_146
}

predicate func_16(Variable vwrk_line_148, NotExpr target_16) {
		target_16.getOperand().(VariableAccess).getTarget()=vwrk_line_148
}

from Function func, Parameter vin_141, Variable vraster_144, Variable vtile_width_146, Variable vtile_height_146, Variable vwrk_line_148, MulExpr target_8, MulExpr target_9, FunctionCall target_10, FunctionCall target_11, AssignAddExpr target_12, EqualityOperation target_13, FunctionCall target_14, AssignAddExpr target_15, NotExpr target_16
where
not func_0(func)
and not func_1(vin_141, vtile_width_146, vtile_height_146, target_10, target_11, target_8, target_9, target_12, func)
and not func_2(vraster_144, target_13, func)
and not func_4(func)
and not func_5(vin_141, vtile_width_146, target_11, target_14, target_9, target_15, func)
and not func_6(vwrk_line_148, target_16, func)
and func_8(vtile_width_146, vtile_height_146, target_8)
and func_9(vtile_width_146, target_9)
and func_10(vin_141, target_10)
and func_11(vin_141, target_11)
and func_12(vtile_height_146, target_12)
and func_13(vraster_144, target_13)
and func_14(vin_141, target_14)
and func_15(vtile_width_146, target_15)
and func_16(vwrk_line_148, target_16)
and vin_141.getType().hasName("TIFF *")
and vraster_144.getType().hasName("uint32 *")
and vtile_width_146.getType().hasName("uint32")
and vtile_height_146.getType().hasName("uint32")
and vwrk_line_148.getType().hasName("uint32 *")
and vin_141.getFunction() = func
and vraster_144.(LocalVariable).getFunction() = func
and vtile_width_146.(LocalVariable).getFunction() = func
and vtile_height_146.(LocalVariable).getFunction() = func
and vwrk_line_148.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
