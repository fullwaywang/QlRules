/**
 * @name libtiff-66e7bd59520996740e4df5495a830b42fae48bc4-TIFFReadRawStrip1
 * @id cpp/libtiff/66e7bd59520996740e4df5495a830b42fae48bc4/TIFFReadRawStrip1
 * @description libtiff-66e7bd59520996740e4df5495a830b42fae48bc4-libtiff/tif_read.c-TIFFReadRawStrip1 CVE-2017-7602
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmb_423, LogicalOrExpr target_13, VariableAccess target_0) {
		target_0.getTarget()=vmb_423
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue() instanceof AddExpr
		and target_0.getLocation().isBefore(target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
}

predicate func_1(Parameter vsize_387, Variable vma_423, ExprStmt target_12, ExprStmt target_5, LogicalOrExpr target_13) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vma_423
		and target_1.getLesserOperand().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getValue()="9223372036854775807"
		and target_1.getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vsize_387
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof AssignExpr
		and target_1.getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_1.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_3(Function func) {
	exists(Initializer target_3 |
		target_3.getExpr() instanceof AddExpr
		and target_3.getExpr().getEnclosingFunction() = func)
}

predicate func_4(Variable vma_423, Variable vn_424, Parameter vtif_387, LogicalOrExpr target_13, PointerArithmeticOperation target_14, ExprStmt target_8, ExprStmt target_15) {
	exists(IfStmt target_4 |
		target_4.getCondition() instanceof RelationalOperation
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_424
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tif_size"
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_387
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vma_423
		and target_4.getElse() instanceof ExprStmt
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_14.getAnOperand().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_15.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vsize_387, Variable vn_424, LogicalOrExpr target_16, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_424
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsize_387
		and target_5.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_16
}

predicate func_6(Variable vtd_390, Variable vma_423, Parameter vstrip_387, AssignExpr target_6) {
		target_6.getLValue().(VariableAccess).getTarget()=vma_423
		and target_6.getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="td_stripoffset"
		and target_6.getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_390
		and target_6.getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vstrip_387
}

predicate func_7(Parameter vsize_387, Variable vma_423, Variable vmb_423, AddExpr target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vma_423
		and target_7.getAnOperand().(VariableAccess).getTarget()=vsize_387
		and target_7.getParent().(AssignExpr).getRValue() = target_7
		and target_7.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmb_423
}

predicate func_8(Variable vn_424, LogicalOrExpr target_16, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_424
		and target_8.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_8.getParent().(IfStmt).getCondition()=target_16
}

predicate func_9(Variable vmb_423, Parameter vtif_387, ExprStmt target_17, RelationalOperation target_9) {
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getGreaterOperand().(VariableAccess).getTarget()=vmb_423
		and target_9.getLesserOperand().(PointerFieldAccess).getTarget().getName()="tif_size"
		and target_9.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_387
		and target_9.getParent().(LogicalOrExpr).getAnOperand() instanceof LogicalOrExpr
		and target_9.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_17
}

predicate func_10(Variable vma_423, VariableAccess target_10) {
		target_10.getTarget()=vma_423
}

predicate func_11(Parameter vsize_387, VariableAccess target_11) {
		target_11.getTarget()=vsize_387
}

predicate func_12(Variable vmb_423, NotExpr target_18, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmb_423
		and target_12.getExpr().(AssignExpr).getRValue() instanceof AddExpr
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
}

predicate func_13(Parameter vsize_387, Variable vma_423, Variable vmb_423, LogicalOrExpr target_13) {
		target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmb_423
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vma_423
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmb_423
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_387
		and target_13.getAnOperand() instanceof RelationalOperation
		and target_13.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof AssignExpr
}

predicate func_14(Variable vma_423, Parameter vtif_387, PointerArithmeticOperation target_14) {
		target_14.getAnOperand().(PointerFieldAccess).getTarget().getName()="tif_base"
		and target_14.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_387
		and target_14.getAnOperand().(VariableAccess).getTarget()=vma_423
}

predicate func_15(Parameter vsize_387, Variable vn_424, Parameter vtif_387, Parameter vstrip_387, ExprStmt target_15) {
		target_15.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_15.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_15.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_387
		and target_15.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_15.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Read error at scanline %lu, strip %lu; got %llu bytes, expected %llu"
		and target_15.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="tif_row"
		and target_15.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_387
		and target_15.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vstrip_387
		and target_15.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vn_424
		and target_15.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vsize_387
}

predicate func_16(Variable vtd_390, Variable vma_423, Parameter vtif_387, Parameter vstrip_387, LogicalOrExpr target_16) {
		target_16.getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="td_stripoffset"
		and target_16.getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtd_390
		and target_16.getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vstrip_387
		and target_16.getAnOperand().(RelationalOperation).getLesserOperand().(BinaryBitwiseOperation).getValue()="9223372036854775807"
		and target_16.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vma_423
		and target_16.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="tif_size"
		and target_16.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_387
}

predicate func_17(Variable vma_423, Variable vn_424, Parameter vtif_387, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_424
		and target_17.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tif_size"
		and target_17.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_387
		and target_17.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vma_423
}

predicate func_18(Parameter vtif_387, NotExpr target_18) {
		target_18.getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tif_flags"
		and target_18.getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_387
		and target_18.getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2048"
		and target_18.getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vsize_387, Variable vtd_390, Variable vma_423, Variable vmb_423, Variable vn_424, Parameter vtif_387, Parameter vstrip_387, VariableAccess target_0, ExprStmt target_5, AssignExpr target_6, AddExpr target_7, ExprStmt target_8, RelationalOperation target_9, VariableAccess target_10, VariableAccess target_11, ExprStmt target_12, LogicalOrExpr target_13, PointerArithmeticOperation target_14, ExprStmt target_15, LogicalOrExpr target_16, ExprStmt target_17, NotExpr target_18
where
func_0(vmb_423, target_13, target_0)
and not func_1(vsize_387, vma_423, target_12, target_5, target_13)
and not func_3(func)
and not func_4(vma_423, vn_424, vtif_387, target_13, target_14, target_8, target_15)
and func_5(vsize_387, vn_424, target_16, target_5)
and func_6(vtd_390, vma_423, vstrip_387, target_6)
and func_7(vsize_387, vma_423, vmb_423, target_7)
and func_8(vn_424, target_16, target_8)
and func_9(vmb_423, vtif_387, target_17, target_9)
and func_10(vma_423, target_10)
and func_11(vsize_387, target_11)
and func_12(vmb_423, target_18, target_12)
and func_13(vsize_387, vma_423, vmb_423, target_13)
and func_14(vma_423, vtif_387, target_14)
and func_15(vsize_387, vn_424, vtif_387, vstrip_387, target_15)
and func_16(vtd_390, vma_423, vtif_387, vstrip_387, target_16)
and func_17(vma_423, vn_424, vtif_387, target_17)
and func_18(vtif_387, target_18)
and vsize_387.getType().hasName("tmsize_t")
and vtd_390.getType().hasName("TIFFDirectory *")
and vma_423.getType().hasName("tmsize_t")
and vmb_423.getType().hasName("tmsize_t")
and vn_424.getType().hasName("tmsize_t")
and vtif_387.getType().hasName("TIFF *")
and vstrip_387.getType().hasName("uint32")
and vsize_387.getFunction() = func
and vtd_390.(LocalVariable).getFunction() = func
and vma_423.(LocalVariable).getFunction() = func
and vmb_423.(LocalVariable).getFunction() = func
and vn_424.(LocalVariable).getFunction() = func
and vtif_387.getFunction() = func
and vstrip_387.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
