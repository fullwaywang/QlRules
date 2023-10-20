/**
 * @name imagemagick-134463b926fa965571aa4febd61b810be5e7da05-ReadVIFFImage
 * @id cpp/imagemagick/134463b926fa965571aa4febd61b810be5e7da05/ReadVIFFImage
 * @description imagemagick-134463b926fa965571aa4febd61b810be5e7da05-coders/viff.c-ReadVIFFImage CVE-2016-10065
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vimage_info_140, Parameter vexception_141, Variable vimage_215, Variable v__func__, EqualityOperation target_7, RelationalOperation target_8, ExprStmt target_9, FunctionCall target_10, ExprStmt target_11) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("CheckMemoryOverflow")
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_215
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rows"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_215
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_141
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_140
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vimage_215
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CloseBlob")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_215
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vimage_215
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyImageList")
		and target_0.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_8.getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_10.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_11.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vimage_info_140, Parameter vexception_141, Variable vimage_215, Variable vnumber_pixels_224, Variable vviff_info_254, Variable v__func__, EqualityOperation target_7, ExprStmt target_12, EqualityOperation target_13, ExprStmt target_5) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("CheckMemoryOverflow")
		and target_1.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnumber_pixels_224
		and target_1.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="number_data_bands"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vviff_info_254
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_141
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_140
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vimage_215
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CloseBlob")
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_215
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vimage_215
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyImageList")
		and target_1.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_13.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_2(EqualityOperation target_7, Function func) {
	exists(EmptyStmt target_2 |
		target_2.toString() = ";"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_2.getEnclosingFunction() = func)
}

predicate func_4(Variable vimage_215, Variable vmax_packets_240, EqualityOperation target_7, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmax_packets_240
		and target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_215
		and target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
		and target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_4.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_215
		and target_4.getParent().(IfStmt).getCondition()=target_7
}

predicate func_5(Variable vnumber_pixels_224, Variable vmax_packets_240, Variable vviff_info_254, EqualityOperation target_7, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmax_packets_240
		and target_5.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vnumber_pixels_224
		and target_5.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="number_data_bands"
		and target_5.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vviff_info_254
		and target_5.getParent().(IfStmt).getCondition()=target_7
}

predicate func_6(Function func, EmptyStmt target_6) {
		target_6.toString() = ";"
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Variable vviff_info_254, EqualityOperation target_7) {
		target_7.getAnOperand().(ValueFieldAccess).getTarget().getName()="data_storage_type"
		and target_7.getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vviff_info_254
		and target_7.getAnOperand().(Literal).getValue()="0"
}

predicate func_8(Parameter vimage_info_140, Variable vimage_215, RelationalOperation target_8) {
		 (target_8 instanceof GEExpr or target_8 instanceof LEExpr)
		and target_8.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="scene"
		and target_8.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_215
		and target_8.getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="scene"
		and target_8.getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_140
		and target_8.getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="number_scenes"
		and target_8.getLesserOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_140
		and target_8.getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_9(Parameter vexception_141, Variable vimage_215, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("SetImageExtent")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_215
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="columns"
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_215
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="rows"
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_215
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vexception_141
}

predicate func_10(Variable vimage_215, FunctionCall target_10) {
		target_10.getTarget().hasName("DestroyImageList")
		and target_10.getArgument(0).(VariableAccess).getTarget()=vimage_215
}

predicate func_11(Parameter vimage_info_140, Parameter vexception_141, Variable v__func__, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_141
		and target_11.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_11.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_11.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_11.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="ColormapTypeNotSupported"
		and target_11.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_11.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_11.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="ColormapTypeNotSupported"
		and target_11.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_11.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_11.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_140
}

predicate func_12(Parameter vimage_info_140, Parameter vexception_141, Variable v__func__, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_141
		and target_12.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_12.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_12.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_12.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_12.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_12.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_12.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_12.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_12.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_12.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_140
}

predicate func_13(Variable vnumber_pixels_224, EqualityOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vnumber_pixels_224
		and target_13.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vimage_info_140, Parameter vexception_141, Variable vimage_215, Variable vnumber_pixels_224, Variable vmax_packets_240, Variable vviff_info_254, Variable v__func__, ExprStmt target_4, ExprStmt target_5, EmptyStmt target_6, EqualityOperation target_7, RelationalOperation target_8, ExprStmt target_9, FunctionCall target_10, ExprStmt target_11, ExprStmt target_12, EqualityOperation target_13
where
not func_0(vimage_info_140, vexception_141, vimage_215, v__func__, target_7, target_8, target_9, target_10, target_11)
and not func_1(vimage_info_140, vexception_141, vimage_215, vnumber_pixels_224, vviff_info_254, v__func__, target_7, target_12, target_13, target_5)
and not func_2(target_7, func)
and func_4(vimage_215, vmax_packets_240, target_7, target_4)
and func_5(vnumber_pixels_224, vmax_packets_240, vviff_info_254, target_7, target_5)
and func_6(func, target_6)
and func_7(vviff_info_254, target_7)
and func_8(vimage_info_140, vimage_215, target_8)
and func_9(vexception_141, vimage_215, target_9)
and func_10(vimage_215, target_10)
and func_11(vimage_info_140, vexception_141, v__func__, target_11)
and func_12(vimage_info_140, vexception_141, v__func__, target_12)
and func_13(vnumber_pixels_224, target_13)
and vimage_info_140.getType().hasName("const ImageInfo *")
and vexception_141.getType().hasName("ExceptionInfo *")
and vimage_215.getType().hasName("Image *")
and vnumber_pixels_224.getType().hasName("MagickSizeType")
and vmax_packets_240.getType().hasName("size_t")
and vviff_info_254.getType().hasName("ViffInfo")
and v__func__.getType() instanceof ArrayType
and vimage_info_140.getParentScope+() = func
and vexception_141.getParentScope+() = func
and vimage_215.getParentScope+() = func
and vnumber_pixels_224.getParentScope+() = func
and vmax_packets_240.getParentScope+() = func
and vviff_info_254.getParentScope+() = func
and not v__func__.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
