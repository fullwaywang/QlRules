/**
 * @name libtiff-7c39352ccd9060d311d3dc9a1f1bc00133a160e6-cvt_by_strip
 * @id cpp/libtiff/7c39352ccd9060d311d3dc9a1f1bc00133a160e6/cvt-by-strip
 * @description libtiff-7c39352ccd9060d311d3dc9a1f1bc00133a160e6-tools/tiff2rgba.c-cvt_by_strip CVE-2016-3945
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

predicate func_1(Parameter vin_244, Variable vwidth_248, Variable vrowsperstrip, FunctionCall target_10, FunctionCall target_11, MulExpr target_8, MulExpr target_9, AssignAddExpr target_12, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vwidth_248
		and target_1.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(DivExpr).getLeftOperand().(VariableAccess).getType().hasName("uint32")
		and target_1.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vrowsperstrip
		and target_1.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("TIFFFileName")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vin_244
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Integer overflow when calculating raster buffer"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_1)
		and target_10.getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getArgument(0).(VariableAccess).getLocation())
		and target_8.getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_9.getLeftOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(DivExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_12.getRValue().(VariableAccess).getLocation()))
}

predicate func_2(Variable vraster_247, EqualityOperation target_13, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vraster_247
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFmalloc")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("uint32")
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_2)
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_4(Function func) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(VariableAccess).getType().hasName("uint32")
		and target_4.getRValue() instanceof MulExpr
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Parameter vin_244, Variable vwidth_248, FunctionCall target_11, FunctionCall target_14, MulExpr target_9, ExprStmt target_15, Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vwidth_248
		and target_5.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getType().hasName("uint32")
		and target_5.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_5.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("TIFFFileName")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vin_244
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Integer overflow when calculating wrk_line buffer"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit")
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_5)
		and target_11.getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_14.getArgument(0).(VariableAccess).getLocation())
		and target_9.getLeftOperand().(VariableAccess).getLocation().isBefore(target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_6(Variable vwrk_line_250, NotExpr target_16, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vwrk_line_250
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFmalloc")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("uint32")
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_6)
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_16.getOperand().(VariableAccess).getLocation()))
}

predicate func_8(Variable vwidth_248, Variable vrowsperstrip, MulExpr target_8) {
		target_8.getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vwidth_248
		and target_8.getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vrowsperstrip
		and target_8.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_8.getRightOperand().(SizeofTypeOperator).getValue()="4"
		and target_8.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFmalloc")
}

predicate func_9(Variable vwidth_248, MulExpr target_9) {
		target_9.getLeftOperand().(VariableAccess).getTarget()=vwidth_248
		and target_9.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_9.getRightOperand().(SizeofTypeOperator).getValue()="4"
		and target_9.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_TIFFmalloc")
}

predicate func_10(Parameter vin_244, FunctionCall target_10) {
		target_10.getTarget().hasName("TIFFFileName")
		and target_10.getArgument(0).(VariableAccess).getTarget()=vin_244
}

predicate func_11(Parameter vin_244, FunctionCall target_11) {
		target_11.getTarget().hasName("TIFFFileName")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vin_244
}

predicate func_12(Variable vrowsperstrip, AssignAddExpr target_12) {
		target_12.getLValue().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_12.getRValue().(VariableAccess).getTarget()=vrowsperstrip
}

predicate func_13(Variable vraster_247, EqualityOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vraster_247
		and target_13.getAnOperand().(Literal).getValue()="0"
}

predicate func_14(Parameter vin_244, FunctionCall target_14) {
		target_14.getTarget().hasName("TIFFFileName")
		and target_14.getArgument(0).(VariableAccess).getTarget()=vin_244
}

predicate func_15(Variable vraster_247, Variable vwidth_248, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32 *")
		and target_15.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vraster_247
		and target_15.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vwidth_248
		and target_15.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_16(Variable vwrk_line_250, NotExpr target_16) {
		target_16.getOperand().(VariableAccess).getTarget()=vwrk_line_250
}

from Function func, Parameter vin_244, Variable vraster_247, Variable vwidth_248, Variable vwrk_line_250, Variable vrowsperstrip, MulExpr target_8, MulExpr target_9, FunctionCall target_10, FunctionCall target_11, AssignAddExpr target_12, EqualityOperation target_13, FunctionCall target_14, ExprStmt target_15, NotExpr target_16
where
not func_0(func)
and not func_1(vin_244, vwidth_248, vrowsperstrip, target_10, target_11, target_8, target_9, target_12, func)
and not func_2(vraster_247, target_13, func)
and not func_4(func)
and not func_5(vin_244, vwidth_248, target_11, target_14, target_9, target_15, func)
and not func_6(vwrk_line_250, target_16, func)
and func_8(vwidth_248, vrowsperstrip, target_8)
and func_9(vwidth_248, target_9)
and func_10(vin_244, target_10)
and func_11(vin_244, target_11)
and func_12(vrowsperstrip, target_12)
and func_13(vraster_247, target_13)
and func_14(vin_244, target_14)
and func_15(vraster_247, vwidth_248, target_15)
and func_16(vwrk_line_250, target_16)
and vin_244.getType().hasName("TIFF *")
and vraster_247.getType().hasName("uint32 *")
and vwidth_248.getType().hasName("uint32")
and vwrk_line_250.getType().hasName("uint32 *")
and vrowsperstrip.getType().hasName("uint32")
and vin_244.getFunction() = func
and vraster_247.(LocalVariable).getFunction() = func
and vwidth_248.(LocalVariable).getFunction() = func
and vwrk_line_250.(LocalVariable).getFunction() = func
and not vrowsperstrip.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
