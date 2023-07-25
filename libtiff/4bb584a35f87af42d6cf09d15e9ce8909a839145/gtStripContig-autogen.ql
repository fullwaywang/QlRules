/**
 * @name libtiff-4bb584a35f87af42d6cf09d15e9ce8909a839145-gtStripContig
 * @id cpp/libtiff/4bb584a35f87af42d6cf09d15e9ce8909a839145/gtStripContig
 * @description libtiff-4bb584a35f87af42d6cf09d15e9ce8909a839145-libtiff/tif_getimage.c-gtStripContig CVE-2019-17546
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("uint32")
		and target_0.getExpr().(AssignExpr).getRValue() instanceof AddExpr
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vtif_916, Variable vrow_918, Variable vbuf_920, Variable vscanline_924, Variable vmaxstripsize_927, BlockStmt target_13, ExprStmt target_14) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vscanline_924
		and target_1.getLesserOperand().(Literal).getValue()="0"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("_TIFFReadEncodedStripAndAllocBuffer")
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_916
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("TIFFComputeStrip")
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_916
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrow_918
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="row_offset"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbuf_920
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxstripsize_927
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(4).(MulExpr).getLeftOperand() instanceof AddExpr
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(4).(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscanline_924
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_1.getParent().(LogicalAndExpr).getAnOperand() instanceof LogicalOrExpr
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_13
		and target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vtif_916, Variable vrow_918, Variable vbuf_920, Variable vscanline_924, Variable vmaxstripsize_927, BlockStmt target_13, ExprStmt target_15) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(VariableAccess).getType().hasName("uint32")
		and target_2.getLesserOperand().(DivExpr).getLeftOperand().(BinaryBitwiseOperation).getValue()="9223372036854775807"
		and target_2.getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vscanline_924
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("_TIFFReadEncodedStripAndAllocBuffer")
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_916
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("TIFFComputeStrip")
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_916
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrow_918
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="row_offset"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbuf_920
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxstripsize_927
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(4).(MulExpr).getLeftOperand() instanceof AddExpr
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(4).(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscanline_924
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_2.getParent().(LogicalAndExpr).getAnOperand() instanceof LogicalOrExpr
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_13
		and target_2.getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vtif_916, LogicalAndExpr target_16, FunctionCall target_17) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_916
		and target_3.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("TIFFFileName")
		and target_3.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_916
		and target_3.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Integer overflow in gtStripContig"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_17.getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(LogicalAndExpr target_16, Function func) {
	exists(ReturnStmt target_4 |
		target_4.getExpr().(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Variable vtif_916, Variable vrow_918, Variable vbuf_920, Variable vscanline_924, Variable vret_926, Variable vmaxstripsize_927, ExprStmt target_14, ExprStmt target_18, LogicalAndExpr target_16, MulExpr target_20, ReturnStmt target_21, ExprStmt target_22) {
	exists(IfStmt target_5 |
		target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("_TIFFReadEncodedStripAndAllocBuffer")
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_916
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("TIFFComputeStrip")
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_916
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrow_918
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="row_offset"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbuf_920
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxstripsize_927
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(4).(MulExpr).getLeftOperand().(VariableAccess).getType().hasName("uint32")
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(4).(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscanline_924
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand() instanceof LogicalOrExpr
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_926
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_18.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_16.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(4).(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_20.getRightOperand().(VariableAccess).getLocation())
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_21.getExpr().(VariableAccess).getLocation())
		and target_22.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_9(Parameter vimg_914, Variable vtif_916, Variable vrow_918, Variable vnrowsub_918, Variable vbuf_920, Variable vscanline_924, Variable vmaxstripsize_927, BlockStmt target_13, LogicalOrExpr target_9) {
		target_9.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_920
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getAnOperand().(PointerFieldAccess).getTarget().getName()="stoponerr"
		and target_9.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_914
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("_TIFFReadEncodedStripAndAllocBuffer")
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_916
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("TIFFComputeStrip")
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_916
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrow_918
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="row_offset"
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbuf_920
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxstripsize_927
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(4).(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnrowsub_918
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(4).(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscanline_924
		and target_9.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_9.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_13
}

/*predicate func_10(Parameter vimg_914, Variable vtif_916, Variable vrow_918, Variable vnrowsub_918, Variable vbuf_920, Variable vrowsperstrip_921, Variable vscanline_924, Variable vmaxstripsize_927, AddExpr target_10) {
		target_10.getAnOperand().(RemExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrow_918
		and target_10.getAnOperand().(RemExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="row_offset"
		and target_10.getAnOperand().(RemExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_914
		and target_10.getAnOperand().(RemExpr).getRightOperand().(VariableAccess).getTarget()=vrowsperstrip_921
		and target_10.getAnOperand().(VariableAccess).getTarget()=vnrowsub_918
		and target_10.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("_TIFFReadEncodedStripAndAllocBuffer")
		and target_10.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_916
		and target_10.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("TIFFComputeStrip")
		and target_10.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_916
		and target_10.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrow_918
		and target_10.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="row_offset"
		and target_10.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_914
		and target_10.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_10.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbuf_920
		and target_10.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxstripsize_927
		and target_10.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(4).(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscanline_924
}

*/
/*predicate func_11(Parameter vimg_914, Variable vtif_916, Variable vrow_918, Variable vnrowsub_918, Variable vbuf_920, Variable vrowsperstrip_921, Variable vscanline_924, Variable vmaxstripsize_927, VariableAccess target_11) {
		target_11.getTarget()=vtif_916
		and target_11.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("_TIFFReadEncodedStripAndAllocBuffer")
		and target_11.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("TIFFComputeStrip")
		and target_11.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_916
		and target_11.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrow_918
		and target_11.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="row_offset"
		and target_11.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_914
		and target_11.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_11.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbuf_920
		and target_11.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxstripsize_927
		and target_11.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(4).(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(RemExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrow_918
		and target_11.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(4).(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(RemExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="row_offset"
		and target_11.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(4).(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(RemExpr).getRightOperand().(VariableAccess).getTarget()=vrowsperstrip_921
		and target_11.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(4).(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnrowsub_918
		and target_11.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(4).(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscanline_924
}

*/
/*predicate func_12(Parameter vimg_914, Variable vtif_916, Variable vrow_918, Variable vnrowsub_918, Variable vbuf_920, Variable vrowsperstrip_921, Variable vscanline_924, Variable vmaxstripsize_927, VariableAccess target_12) {
		target_12.getTarget()=vscanline_924
		and target_12.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("_TIFFReadEncodedStripAndAllocBuffer")
		and target_12.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_916
		and target_12.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("TIFFComputeStrip")
		and target_12.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_916
		and target_12.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrow_918
		and target_12.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="row_offset"
		and target_12.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_914
		and target_12.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_12.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbuf_920
		and target_12.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxstripsize_927
		and target_12.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(4).(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(RemExpr).getRightOperand().(VariableAccess).getTarget()=vrowsperstrip_921
		and target_12.getParent().(MulExpr).getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(4).(MulExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnrowsub_918
}

*/
predicate func_13(Variable vret_926, BlockStmt target_13) {
		target_13.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_926
		and target_13.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_14(Variable vtif_916, Variable vscanline_924, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vscanline_924
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFScanlineSize")
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_916
}

predicate func_15(Parameter vimg_914, Variable vrow_918, Variable vrowsperstrip_921, Variable vscanline_924, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(RemExpr).getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrow_918
		and target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(RemExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="row_offset"
		and target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(RemExpr).getRightOperand().(VariableAccess).getTarget()=vrowsperstrip_921
		and target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscanline_924
		and target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="col_offset"
		and target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_914
		and target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="samplesperpixel"
		and target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_914
}

predicate func_16(Parameter vimg_914, Variable vtif_916, Variable vrow_918, Variable vbuf_920, Variable vscanline_924, Variable vmaxstripsize_927, LogicalAndExpr target_16) {
		target_16.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("_TIFFReadEncodedStripAndAllocBuffer")
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_916
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("TIFFComputeStrip")
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_916
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrow_918
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="row_offset"
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_914
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbuf_920
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxstripsize_927
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(4).(MulExpr).getLeftOperand() instanceof AddExpr
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(4).(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscanline_924
		and target_16.getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_16.getAnOperand() instanceof LogicalOrExpr
}

predicate func_17(Parameter vimg_914, Variable vtif_916, Variable vrow_918, FunctionCall target_17) {
		target_17.getTarget().hasName("TIFFComputeStrip")
		and target_17.getArgument(0).(VariableAccess).getTarget()=vtif_916
		and target_17.getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrow_918
		and target_17.getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="row_offset"
		and target_17.getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimg_914
		and target_17.getArgument(2).(Literal).getValue()="0"
}

predicate func_18(Variable vrow_918, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_18.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vrow_918
		and target_18.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_18.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_18.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(SubExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_18.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vrow_918
		and target_18.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(VariableAccess).getTarget().getType().hasName("uint32")
}

predicate func_20(Variable vscanline_924, MulExpr target_20) {
		target_20.getLeftOperand() instanceof AddExpr
		and target_20.getRightOperand().(VariableAccess).getTarget()=vscanline_924
}

predicate func_21(Variable vret_926, ReturnStmt target_21) {
		target_21.getExpr().(VariableAccess).getTarget()=vret_926
}

predicate func_22(Variable vtif_916, Variable vmaxstripsize_927, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmaxstripsize_927
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFStripSize")
		and target_22.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_916
}

from Function func, Parameter vimg_914, Variable vtif_916, Variable vrow_918, Variable vnrowsub_918, Variable vbuf_920, Variable vrowsperstrip_921, Variable vscanline_924, Variable vret_926, Variable vmaxstripsize_927, LogicalOrExpr target_9, BlockStmt target_13, ExprStmt target_14, ExprStmt target_15, LogicalAndExpr target_16, FunctionCall target_17, ExprStmt target_18, MulExpr target_20, ReturnStmt target_21, ExprStmt target_22
where
not func_0(func)
and not func_1(vtif_916, vrow_918, vbuf_920, vscanline_924, vmaxstripsize_927, target_13, target_14)
and not func_2(vtif_916, vrow_918, vbuf_920, vscanline_924, vmaxstripsize_927, target_13, target_15)
and not func_3(vtif_916, target_16, target_17)
and not func_4(target_16, func)
and not func_5(vtif_916, vrow_918, vbuf_920, vscanline_924, vret_926, vmaxstripsize_927, target_14, target_18, target_16, target_20, target_21, target_22)
and func_9(vimg_914, vtif_916, vrow_918, vnrowsub_918, vbuf_920, vscanline_924, vmaxstripsize_927, target_13, target_9)
and func_13(vret_926, target_13)
and func_14(vtif_916, vscanline_924, target_14)
and func_15(vimg_914, vrow_918, vrowsperstrip_921, vscanline_924, target_15)
and func_16(vimg_914, vtif_916, vrow_918, vbuf_920, vscanline_924, vmaxstripsize_927, target_16)
and func_17(vimg_914, vtif_916, vrow_918, target_17)
and func_18(vrow_918, target_18)
and func_20(vscanline_924, target_20)
and func_21(vret_926, target_21)
and func_22(vtif_916, vmaxstripsize_927, target_22)
and vimg_914.getType().hasName("TIFFRGBAImage *")
and vtif_916.getType().hasName("TIFF *")
and vrow_918.getType().hasName("uint32")
and vnrowsub_918.getType().hasName("uint32")
and vbuf_920.getType().hasName("unsigned char *")
and vrowsperstrip_921.getType().hasName("uint32")
and vscanline_924.getType().hasName("tmsize_t")
and vret_926.getType().hasName("int")
and vmaxstripsize_927.getType().hasName("tmsize_t")
and vimg_914.getFunction() = func
and vtif_916.(LocalVariable).getFunction() = func
and vrow_918.(LocalVariable).getFunction() = func
and vnrowsub_918.(LocalVariable).getFunction() = func
and vbuf_920.(LocalVariable).getFunction() = func
and vrowsperstrip_921.(LocalVariable).getFunction() = func
and vscanline_924.(LocalVariable).getFunction() = func
and vret_926.(LocalVariable).getFunction() = func
and vmaxstripsize_927.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
