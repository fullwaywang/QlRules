/**
 * @name libtiff-83a4b92815ea04969d494416eaae3d4c6b338e4a-t2p_process_jpeg_strip
 * @id cpp/libtiff/83a4b92815ea04969d494416eaae3d4c6b338e4a/t2p-process-jpeg-strip
 * @description libtiff-83a4b92815ea04969d494416eaae3d4c6b338e4a-tools/tiff2pdf.c-t2p_process_jpeg_strip CVE-2016-9533
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbufferoffset_3442, BlockStmt target_13, ExprStmt target_14) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getGreaterOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
		and target_0.getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_0.getLesserOperand().(VariableAccess).getType().hasName("tsize_t")
		and target_0.getParent().(IfStmt).getThen()=target_13
		and target_14.getExpr().(AssignAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vbufferoffset_3442, Variable vdatalen_3449, EqualityOperation target_10, AddressOfExpr target_15, LogicalOrExpr target_16, AddExpr target_17) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdatalen_3449
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="6"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("tsize_t")
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_15.getOperand().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_16.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_17.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vbufferoffset_3442, EqualityOperation target_10, AddressOfExpr target_15, ExprStmt target_18) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="9"
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("tsize_t")
		and target_2.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_15.getOperand().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vbufferoffset_3442, Variable vncomp_3454, EqualityOperation target_10, ExprStmt target_18, ArrayExpr target_19, LogicalOrExpr target_20, RelationalOperation target_21) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="11"
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="3"
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vncomp_3454
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("tsize_t")
		and target_3.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(7)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_18.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_19.getArrayOffset().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_20.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_21.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vbufferoffset_3442, Variable vdatalen_3449, ArrayExpr target_22, AddressOfExpr target_23, ExprStmt target_24, AddExpr target_25) {
	exists(IfStmt target_4 |
		target_4.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdatalen_3449
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("tsize_t")
		and target_4.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_22
		and target_23.getOperand().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_4.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_24.getExpr().(AssignAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_25.getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vstrip_3439, Parameter vbuffer_3441, Parameter vbufferoffset_3442, Variable vdatalen_3449, ArrayExpr target_22, AddressOfExpr target_26, AddressOfExpr target_27, AddressOfExpr target_23, AddressOfExpr target_28, AddressOfExpr target_29, ExprStmt target_30, ExprStmt target_24, ExprStmt target_31) {
	exists(IfStmt target_5 |
		target_5.getCondition() instanceof EqualityOperation
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdatalen_3449
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("tsize_t")
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFmemcpy")
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_3441
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstrip_3439
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdatalen_3449
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdatalen_3449
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_5.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
		and target_5.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_5.getElse().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("tsize_t")
		and target_5.getElse().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_5.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_3441
		and target_5.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(HexLiteral).getValue()="255"
		and target_5.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_3441
		and target_5.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(HexLiteral).getValue()="208"
		and target_5.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(RemExpr).getRightOperand().(Literal).getValue()="8"
		and target_5.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_22
		and target_26.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_27.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_23.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_28.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_29.getOperand().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_30.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_24.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_5.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_31.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_6(Parameter vbufferoffset_3442, Variable vdatalen_3449, EqualityOperation target_11, ExprStmt target_24, AddressOfExpr target_29, AddExpr target_32) {
	exists(IfStmt target_6 |
		target_6.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
		and target_6.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdatalen_3449
		and target_6.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_6.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("tsize_t")
		and target_6.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_24.getExpr().(AssignAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_6.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_6.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_29.getOperand().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_6.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_32.getAnOperand().(VariableAccess).getLocation()))
}

*/
/*predicate func_7(Parameter vbufferoffset_3442, EqualityOperation target_11, ExprStmt target_33, ExprStmt target_30) {
	exists(IfStmt target_7 |
		target_7.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
		and target_7.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_7.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("tsize_t")
		and target_7.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_33.getExpr().(AssignAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_7.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_7.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_30.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

*/
predicate func_8(Parameter vstriplength_3440, Parameter vbufferoffset_3442, Variable vi_3446, ArrayExpr target_22, LogicalOrExpr target_16, SubExpr target_34, ExprStmt target_35, AddressOfExpr target_28, ExprStmt target_31, AddressOfExpr target_27) {
	exists(IfStmt target_8 |
		target_8.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
		and target_8.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vstriplength_3440
		and target_8.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vi_3446
		and target_8.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("tsize_t")
		and target_8.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_8.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_22
		and target_16.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_8.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_8.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_34.getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_35.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_8.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_8.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_28.getOperand().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_31.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_8.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_8.getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_27.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_10(Parameter vno_3443, BlockStmt target_13, EqualityOperation target_10) {
		target_10.getAnOperand().(VariableAccess).getTarget()=vno_3443
		and target_10.getAnOperand().(Literal).getValue()="0"
		and target_10.getParent().(IfStmt).getThen()=target_13
}

predicate func_11(Parameter vno_3443, BlockStmt target_36, EqualityOperation target_11) {
		target_11.getAnOperand().(VariableAccess).getTarget()=vno_3443
		and target_11.getAnOperand().(Literal).getValue()="0"
		and target_11.getParent().(IfStmt).getThen()=target_36
}

predicate func_12(Function func, ReturnStmt target_12) {
		target_12.getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_12
}

predicate func_13(Parameter vstrip_3439, Parameter vbuffer_3441, Parameter vbufferoffset_3442, Variable vi_3446, Variable vdatalen_3449, BlockStmt target_13) {
		target_13.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFmemcpy")
		and target_13.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_3441
		and target_13.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
		and target_13.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstrip_3439
		and target_13.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vi_3446
		and target_13.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_13.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdatalen_3449
		and target_13.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="2"
}

predicate func_14(Parameter vbufferoffset_3442, ExprStmt target_14) {
		target_14.getExpr().(AssignAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
		and target_14.getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="2"
}

predicate func_15(Parameter vbuffer_3441, Parameter vbufferoffset_3442, AddressOfExpr target_15) {
		target_15.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_3441
		and target_15.getOperand().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
}

predicate func_16(Parameter vstriplength_3440, Variable vi_3446, Variable vdatalen_3449, LogicalOrExpr target_16) {
		target_16.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vdatalen_3449
		and target_16.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2"
		and target_16.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdatalen_3449
		and target_16.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vstriplength_3440
		and target_16.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vi_3446
}

predicate func_17(Variable vdatalen_3449, AddExpr target_17) {
		target_17.getAnOperand().(VariableAccess).getTarget()=vdatalen_3449
		and target_17.getAnOperand().(Literal).getValue()="2"
}

predicate func_18(Parameter vbuffer_3441, Parameter vbufferoffset_3442, Variable vncomp_3454, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vncomp_3454
		and target_18.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_3441
		and target_18.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
		and target_18.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="9"
}

predicate func_19(Parameter vbuffer_3441, Parameter vbufferoffset_3442, ArrayExpr target_19) {
		target_19.getArrayBase().(VariableAccess).getTarget()=vbuffer_3441
		and target_19.getArrayOffset().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
		and target_19.getArrayOffset().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="11"
		and target_19.getArrayOffset().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="3"
		and target_19.getArrayOffset().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_20(Variable vncomp_3454, LogicalOrExpr target_20) {
		target_20.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vncomp_3454
		and target_20.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_20.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vncomp_3454
		and target_20.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
}

predicate func_21(Variable vncomp_3454, RelationalOperation target_21) {
		 (target_21 instanceof GTExpr or target_21 instanceof LTExpr)
		and target_21.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_21.getGreaterOperand().(VariableAccess).getTarget()=vncomp_3454
}

predicate func_22(Parameter vstrip_3439, Variable vi_3446, ArrayExpr target_22) {
		target_22.getArrayBase().(VariableAccess).getTarget()=vstrip_3439
		and target_22.getArrayOffset().(VariableAccess).getTarget()=vi_3446
}

predicate func_23(Parameter vbuffer_3441, Parameter vbufferoffset_3442, AddressOfExpr target_23) {
		target_23.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_3441
		and target_23.getOperand().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
}

predicate func_24(Parameter vbufferoffset_3442, Variable vdatalen_3449, ExprStmt target_24) {
		target_24.getExpr().(AssignAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
		and target_24.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdatalen_3449
		and target_24.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="2"
}

predicate func_25(Variable vdatalen_3449, AddExpr target_25) {
		target_25.getAnOperand().(VariableAccess).getTarget()=vdatalen_3449
		and target_25.getAnOperand().(Literal).getValue()="2"
}

predicate func_26(Parameter vstrip_3439, Variable vi_3446, AddressOfExpr target_26) {
		target_26.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstrip_3439
		and target_26.getOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vi_3446
		and target_26.getOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_27(Parameter vstrip_3439, Variable vi_3446, AddressOfExpr target_27) {
		target_27.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstrip_3439
		and target_27.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_3446
}

predicate func_28(Parameter vbuffer_3441, Parameter vbufferoffset_3442, AddressOfExpr target_28) {
		target_28.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_3441
		and target_28.getOperand().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
}

predicate func_29(Parameter vbuffer_3441, Parameter vbufferoffset_3442, AddressOfExpr target_29) {
		target_29.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_3441
		and target_29.getOperand().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
}

predicate func_30(Parameter vbuffer_3441, Parameter vbufferoffset_3442, ExprStmt target_30) {
		target_30.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_3441
		and target_30.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
		and target_30.getExpr().(AssignExpr).getRValue().(HexLiteral).getValue()="255"
}

predicate func_31(Variable vi_3446, Variable vdatalen_3449, ExprStmt target_31) {
		target_31.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vi_3446
		and target_31.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdatalen_3449
		and target_31.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_32(Variable vdatalen_3449, AddExpr target_32) {
		target_32.getAnOperand().(VariableAccess).getTarget()=vdatalen_3449
		and target_32.getAnOperand().(Literal).getValue()="2"
}

predicate func_33(Parameter vbufferoffset_3442, Variable vdatalen_3449, ExprStmt target_33) {
		target_33.getExpr().(AssignAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
		and target_33.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdatalen_3449
		and target_33.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="2"
}

predicate func_34(Parameter vstriplength_3440, Variable vi_3446, SubExpr target_34) {
		target_34.getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vstriplength_3440
		and target_34.getRightOperand().(VariableAccess).getTarget()=vi_3446
}

predicate func_35(Parameter vbuffer_3441, Parameter vbufferoffset_3442, Parameter vno_3443, ExprStmt target_35) {
		target_35.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_3441
		and target_35.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
		and target_35.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(HexLiteral).getValue()="208"
		and target_35.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(RemExpr).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vno_3443
		and target_35.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(RemExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_35.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(RemExpr).getRightOperand().(Literal).getValue()="8"
}

predicate func_36(Parameter vstrip_3439, Parameter vbuffer_3441, Parameter vbufferoffset_3442, Variable vi_3446, Variable vdatalen_3449, BlockStmt target_36) {
		target_36.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFmemcpy")
		and target_36.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_3441
		and target_36.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vbufferoffset_3442
		and target_36.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vstrip_3439
		and target_36.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vi_3446
		and target_36.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_36.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vdatalen_3449
		and target_36.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="2"
}

from Function func, Parameter vstrip_3439, Parameter vstriplength_3440, Parameter vbuffer_3441, Parameter vbufferoffset_3442, Parameter vno_3443, Variable vi_3446, Variable vdatalen_3449, Variable vncomp_3454, EqualityOperation target_10, EqualityOperation target_11, ReturnStmt target_12, BlockStmt target_13, ExprStmt target_14, AddressOfExpr target_15, LogicalOrExpr target_16, AddExpr target_17, ExprStmt target_18, ArrayExpr target_19, LogicalOrExpr target_20, RelationalOperation target_21, ArrayExpr target_22, AddressOfExpr target_23, ExprStmt target_24, AddExpr target_25, AddressOfExpr target_26, AddressOfExpr target_27, AddressOfExpr target_28, AddressOfExpr target_29, ExprStmt target_30, ExprStmt target_31, AddExpr target_32, ExprStmt target_33, SubExpr target_34, ExprStmt target_35, BlockStmt target_36
where
not func_0(vbufferoffset_3442, target_13, target_14)
and not func_1(vbufferoffset_3442, vdatalen_3449, target_10, target_15, target_16, target_17)
and not func_2(vbufferoffset_3442, target_10, target_15, target_18)
and not func_3(vbufferoffset_3442, vncomp_3454, target_10, target_18, target_19, target_20, target_21)
and not func_4(vbufferoffset_3442, vdatalen_3449, target_22, target_23, target_24, target_25)
and not func_5(vstrip_3439, vbuffer_3441, vbufferoffset_3442, vdatalen_3449, target_22, target_26, target_27, target_23, target_28, target_29, target_30, target_24, target_31)
and not func_8(vstriplength_3440, vbufferoffset_3442, vi_3446, target_22, target_16, target_34, target_35, target_28, target_31, target_27)
and func_10(vno_3443, target_13, target_10)
and func_11(vno_3443, target_36, target_11)
and func_12(func, target_12)
and func_13(vstrip_3439, vbuffer_3441, vbufferoffset_3442, vi_3446, vdatalen_3449, target_13)
and func_14(vbufferoffset_3442, target_14)
and func_15(vbuffer_3441, vbufferoffset_3442, target_15)
and func_16(vstriplength_3440, vi_3446, vdatalen_3449, target_16)
and func_17(vdatalen_3449, target_17)
and func_18(vbuffer_3441, vbufferoffset_3442, vncomp_3454, target_18)
and func_19(vbuffer_3441, vbufferoffset_3442, target_19)
and func_20(vncomp_3454, target_20)
and func_21(vncomp_3454, target_21)
and func_22(vstrip_3439, vi_3446, target_22)
and func_23(vbuffer_3441, vbufferoffset_3442, target_23)
and func_24(vbufferoffset_3442, vdatalen_3449, target_24)
and func_25(vdatalen_3449, target_25)
and func_26(vstrip_3439, vi_3446, target_26)
and func_27(vstrip_3439, vi_3446, target_27)
and func_28(vbuffer_3441, vbufferoffset_3442, target_28)
and func_29(vbuffer_3441, vbufferoffset_3442, target_29)
and func_30(vbuffer_3441, vbufferoffset_3442, target_30)
and func_31(vi_3446, vdatalen_3449, target_31)
and func_32(vdatalen_3449, target_32)
and func_33(vbufferoffset_3442, vdatalen_3449, target_33)
and func_34(vstriplength_3440, vi_3446, target_34)
and func_35(vbuffer_3441, vbufferoffset_3442, vno_3443, target_35)
and func_36(vstrip_3439, vbuffer_3441, vbufferoffset_3442, vi_3446, vdatalen_3449, target_36)
and vstrip_3439.getType().hasName("unsigned char *")
and vstriplength_3440.getType().hasName("tsize_t *")
and vbuffer_3441.getType().hasName("unsigned char *")
and vbufferoffset_3442.getType().hasName("tsize_t *")
and vno_3443.getType().hasName("tstrip_t")
and vi_3446.getType().hasName("tsize_t")
and vdatalen_3449.getType().hasName("tsize_t")
and vncomp_3454.getType().hasName("int")
and vstrip_3439.getFunction() = func
and vstriplength_3440.getFunction() = func
and vbuffer_3441.getFunction() = func
and vbufferoffset_3442.getFunction() = func
and vno_3443.getFunction() = func
and vi_3446.(LocalVariable).getFunction() = func
and vdatalen_3449.(LocalVariable).getFunction() = func
and vncomp_3454.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
