/**
 * @name imagemagick-078e9692a257e7a8aa36ccc750927f9617923061-ReadRLEImage
 * @id cpp/imagemagick/078e9692a257e7a8aa36ccc750927f9617923061/ReadRLEImage
 * @description imagemagick-078e9692a257e7a8aa36ccc750927f9617923061-coders/rle.c-ReadRLEImage CVE-2017-11360
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vimage_info_127, Parameter vexception_127, Variable vimage_148, Variable vpixel_info_162, Variable vbits_per_pixel_180, Variable vcolormap_195, Variable v__func__, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, LogicalOrExpr target_6, ExprStmt target_7) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("GetBlobSize")
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_148
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(DivExpr).getLeftOperand().(DivExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vbits_per_pixel_180
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(DivExpr).getLeftOperand().(DivExpr).getRightOperand().(Literal).getValue()="8"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(DivExpr).getRightOperand().(FunctionCall).getTarget().hasName("GetBlobSize")
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(DivExpr).getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_148
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="254.0"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcolormap_195
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcolormap_195
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelinquishMagickMemory")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcolormap_195
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpixel_info_162
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpixel_info_162
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelinquishVirtualMemory")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpixel_info_162
		and target_0.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_0.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_127
		and target_0.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_0.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_0.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="InsufficientImageDataInFile"
		and target_0.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_0.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_0.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_127
		and target_0.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vimage_148
		and target_0.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CloseBlob")
		and target_0.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(3).(EmptyStmt).toString() = ";"
		and target_2.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(DivExpr).getLeftOperand().(DivExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vimage_info_127, Parameter vexception_127, Variable vimage_148, Variable vpixel_info_162, Variable vmap_length_181, Variable vnumber_colormaps_182, Variable vcolormap_195, Variable v__func__, ExprStmt target_8, EqualityOperation target_9, RelationalOperation target_10, ExprStmt target_11, RelationalOperation target_12, EqualityOperation target_13, EqualityOperation target_14) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vnumber_colormaps_182
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vmap_length_181
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("GetBlobSize")
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_148
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcolormap_195
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcolormap_195
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelinquishMagickMemory")
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcolormap_195
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpixel_info_162
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpixel_info_162
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelinquishVirtualMemory")
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpixel_info_162
		and target_1.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_1.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_127
		and target_1.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_1.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_1.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_1.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="InsufficientImageDataInFile"
		and target_1.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_1.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_1.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_127
		and target_1.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vimage_148
		and target_1.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CloseBlob")
		and target_1.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(3).(EmptyStmt).toString() = ";"
		and target_1.getThen().(BlockStmt).getStmt(2).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_9.getAnOperand().(VariableAccess).getLocation())
		and target_10.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_12.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_14.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vimage_info_127, Parameter vexception_127, Variable v__func__, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_127
		and target_2.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_2.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_2.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_2.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_2.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_2.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_2.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_2.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_127
}

predicate func_3(Parameter vexception_127, Variable vimage_148, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("SetImageProperty")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_148
		and target_3.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="comment"
		and target_3.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vexception_127
}

predicate func_4(Variable vimage_148, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("ReadBlobByte")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_148
}

predicate func_5(Variable vpixel_info_162, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpixel_info_162
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelinquishVirtualMemory")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpixel_info_162
}

predicate func_6(Variable vimage_148, Variable vbits_per_pixel_180, Variable vnumber_colormaps_182, LogicalOrExpr target_6) {
		target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="4"
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnumber_colormaps_182
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="254"
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbits_per_pixel_180
		and target_6.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="8"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_148
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_7(Variable vcolormap_195, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcolormap_195
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelinquishMagickMemory")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcolormap_195
}

predicate func_8(Parameter vimage_info_127, Parameter vexception_127, Variable v__func__, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_127
		and target_8.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_8.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_8.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="UnexpectedEndOfFile"
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="UnexpectedEndOfFile"
		and target_8.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_8.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_8.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_127
}

predicate func_9(Variable vpixel_info_162, EqualityOperation target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget()=vpixel_info_162
		and target_9.getAnOperand().(Literal).getValue()="0"
}

predicate func_10(Variable vmap_length_181, RelationalOperation target_10) {
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getGreaterOperand().(VariableAccess).getTarget()=vmap_length_181
}

predicate func_11(Variable vmap_length_181, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vmap_length_181
		and target_11.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_12(Variable vnumber_colormaps_182, RelationalOperation target_12) {
		 (target_12 instanceof GTExpr or target_12 instanceof LTExpr)
		and target_12.getGreaterOperand().(VariableAccess).getTarget()=vnumber_colormaps_182
}

predicate func_13(Variable vnumber_colormaps_182, EqualityOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vnumber_colormaps_182
		and target_13.getAnOperand().(Literal).getValue()="0"
}

predicate func_14(Variable vcolormap_195, EqualityOperation target_14) {
		target_14.getAnOperand().(VariableAccess).getTarget()=vcolormap_195
		and target_14.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vimage_info_127, Parameter vexception_127, Variable vimage_148, Variable vpixel_info_162, Variable vbits_per_pixel_180, Variable vmap_length_181, Variable vnumber_colormaps_182, Variable vcolormap_195, Variable v__func__, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, LogicalOrExpr target_6, ExprStmt target_7, ExprStmt target_8, EqualityOperation target_9, RelationalOperation target_10, ExprStmt target_11, RelationalOperation target_12, EqualityOperation target_13, EqualityOperation target_14
where
not func_0(vimage_info_127, vexception_127, vimage_148, vpixel_info_162, vbits_per_pixel_180, vcolormap_195, v__func__, target_2, target_3, target_4, target_5, target_6, target_7)
and not func_1(vimage_info_127, vexception_127, vimage_148, vpixel_info_162, vmap_length_181, vnumber_colormaps_182, vcolormap_195, v__func__, target_8, target_9, target_10, target_11, target_12, target_13, target_14)
and func_2(vimage_info_127, vexception_127, v__func__, target_2)
and func_3(vexception_127, vimage_148, target_3)
and func_4(vimage_148, target_4)
and func_5(vpixel_info_162, target_5)
and func_6(vimage_148, vbits_per_pixel_180, vnumber_colormaps_182, target_6)
and func_7(vcolormap_195, target_7)
and func_8(vimage_info_127, vexception_127, v__func__, target_8)
and func_9(vpixel_info_162, target_9)
and func_10(vmap_length_181, target_10)
and func_11(vmap_length_181, target_11)
and func_12(vnumber_colormaps_182, target_12)
and func_13(vnumber_colormaps_182, target_13)
and func_14(vcolormap_195, target_14)
and vimage_info_127.getType().hasName("const ImageInfo *")
and vexception_127.getType().hasName("ExceptionInfo *")
and vimage_148.getType().hasName("Image *")
and vpixel_info_162.getType().hasName("MemoryInfo *")
and vbits_per_pixel_180.getType().hasName("size_t")
and vmap_length_181.getType().hasName("size_t")
and vnumber_colormaps_182.getType().hasName("size_t")
and vcolormap_195.getType().hasName("unsigned char *")
and v__func__.getType() instanceof ArrayType
and vimage_info_127.getParentScope+() = func
and vexception_127.getParentScope+() = func
and vimage_148.getParentScope+() = func
and vpixel_info_162.getParentScope+() = func
and vbits_per_pixel_180.getParentScope+() = func
and vmap_length_181.getParentScope+() = func
and vnumber_colormaps_182.getParentScope+() = func
and vcolormap_195.getParentScope+() = func
and not v__func__.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
