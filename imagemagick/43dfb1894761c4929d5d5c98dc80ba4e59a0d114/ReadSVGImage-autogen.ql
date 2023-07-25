/**
 * @name imagemagick-43dfb1894761c4929d5d5c98dc80ba4e59a0d114-ReadSVGImage
 * @id cpp/imagemagick/43dfb1894761c4929d5d5c98dc80ba4e59a0d114/ReadSVGImage
 * @description imagemagick-43dfb1894761c4929d5d5c98dc80ba4e59a0d114-coders/svg.c-ReadSVGImage CVE-2021-3596
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsvg_info_3209, RelationalOperation target_9, ExprStmt target_10, ExprStmt target_11) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="parser"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsvg_info_3209
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_0.getThen().(BlockStmt).getStmt(2) instanceof BlockStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vimage_3198, Variable vsvg_info_3209, EqualityOperation target_12, EqualityOperation target_13, ExprStmt target_14, ExprStmt target_15, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="parser"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsvg_info_3209
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vimage_3198
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyImage")
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_3198
		and target_1.getThen().(BlockStmt).getStmt(3).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(69)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(69).getFollowingStmt()=target_1)
		and target_12.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_15.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vsvg_info_3209, ExprStmt target_16, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsvg_info_3209
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroySVGInfo")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsvg_info_3209
		and (func.getEntryPoint().(BlockStmt).getStmt(83)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(83).getFollowingStmt()=target_2)
		and target_16.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_3(Variable vfilename_3189, ExprStmt target_17, ExprStmt target_7, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("RelinquishUniqueFileResource")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfilename_3189
		and (func.getEntryPoint().(BlockStmt).getStmt(84)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(84).getFollowingStmt()=target_3)
		and target_17.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(Variable voption_3192, Parameter vimage_info_3186, RelationalOperation target_9, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voption_3192
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("GetImageOption")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_info_3186
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="svg:xml-parse-huge"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

predicate func_5(Variable voption_3192, Variable vsvg_info_3209, RelationalOperation target_9, IfStmt target_5) {
		target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=voption_3192
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("IsStringTrue")
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voption_3192
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlCtxtUseOptions")
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="parser"
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsvg_info_3209
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

predicate func_6(Variable vsvg_info_3209, Function func, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsvg_info_3209
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroySVGInfo")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsvg_info_3209
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_7(Variable vfilename_3189, Function func, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("RelinquishUniqueFileResource")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfilename_3189
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(Variable vimage_3198, Variable vstatus_3202, Variable vn_3206, Variable vmessage_3212, RelationalOperation target_9, BlockStmt target_8) {
		target_8.getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_3206
		and target_8.getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReadBlob")
		and target_8.getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_3198
		and target_8.getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SubExpr).getValue()="4095"
		and target_8.getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vmessage_3212
		and target_8.getStmt(0).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getStmt(0).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vmessage_3212
		and target_8.getStmt(0).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_3206
		and target_8.getStmt(0).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_8.getStmt(0).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstatus_3202
		and target_8.getStmt(0).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlParseChunk")
		and target_8.getStmt(0).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="parser"
		and target_8.getStmt(0).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmessage_3212
		and target_8.getStmt(0).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vn_3206
		and target_8.getStmt(0).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_8.getStmt(0).(WhileStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstatus_3202
		and target_8.getStmt(0).(WhileStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getStmt(0).(WhileStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BreakStmt).toString() = "break;"
		and target_8.getStmt(1).(LabelStmt).toString() = "label ...:"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

predicate func_9(Variable vn_3206, RelationalOperation target_9) {
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getGreaterOperand().(VariableAccess).getTarget()=vn_3206
		and target_9.getLesserOperand().(Literal).getValue()="0"
}

predicate func_10(Variable vimage_3198, Variable vn_3206, Variable vsvg_info_3209, Variable vmessage_3212, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="parser"
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsvg_info_3209
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlCreatePushParserCtxt")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsvg_info_3209
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vmessage_3212
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vn_3206
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="filename"
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_3198
}

predicate func_11(Variable vsvg_info_3209, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("xmlCtxtUseOptions")
		and target_11.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="parser"
		and target_11.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsvg_info_3209
}

predicate func_12(Variable vimage_3198, Variable vn_3206, Variable vmessage_3212, EqualityOperation target_12) {
		target_12.getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_3206
		and target_12.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReadBlob")
		and target_12.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_3198
		and target_12.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SubExpr).getValue()="4095"
		and target_12.getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vmessage_3212
		and target_12.getAnOperand().(Literal).getValue()="0"
}

predicate func_13(Variable vimage_3198, EqualityOperation target_13) {
		target_13.getAnOperand().(PointerFieldAccess).getTarget().getName()="debug"
		and target_13.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_3198
}

predicate func_14(Variable vstatus_3202, Variable vn_3206, Variable vsvg_info_3209, Variable vmessage_3212, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstatus_3202
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlParseChunk")
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="parser"
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsvg_info_3209
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmessage_3212
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vn_3206
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
}

predicate func_15(Variable vsvg_info_3209, Variable vmessage_3212, ExprStmt target_15) {
		target_15.getExpr().(FunctionCall).getTarget().hasName("xmlParseChunk")
		and target_15.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="parser"
		and target_15.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsvg_info_3209
		and target_15.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmessage_3212
		and target_15.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_15.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="1"
}

predicate func_16(Variable vimage_3198, Variable vsvg_info_3209, ExprStmt target_16) {
		target_16.getExpr().(FunctionCall).getTarget().hasName("SetImageProperty")
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_3198
		and target_16.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="svg:comment"
		and target_16.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="comment"
		and target_16.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsvg_info_3209
}

predicate func_17(Variable vfilename_3189, ExprStmt target_17) {
		target_17.getExpr().(FunctionCall).getTarget().hasName("FormatLocaleString")
		and target_17.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="filename"
		and target_17.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4096"
		and target_17.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="mvg:%s"
		and target_17.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vfilename_3189
}

from Function func, Variable vfilename_3189, Variable voption_3192, Variable vimage_3198, Variable vstatus_3202, Variable vn_3206, Variable vsvg_info_3209, Variable vmessage_3212, Parameter vimage_info_3186, ExprStmt target_4, IfStmt target_5, ExprStmt target_6, ExprStmt target_7, BlockStmt target_8, RelationalOperation target_9, ExprStmt target_10, ExprStmt target_11, EqualityOperation target_12, EqualityOperation target_13, ExprStmt target_14, ExprStmt target_15, ExprStmt target_16, ExprStmt target_17
where
not func_0(vsvg_info_3209, target_9, target_10, target_11)
and not func_1(vimage_3198, vsvg_info_3209, target_12, target_13, target_14, target_15, func)
and not func_2(vsvg_info_3209, target_16, func)
and not func_3(vfilename_3189, target_17, target_7, func)
and func_4(voption_3192, vimage_info_3186, target_9, target_4)
and func_5(voption_3192, vsvg_info_3209, target_9, target_5)
and func_6(vsvg_info_3209, func, target_6)
and func_7(vfilename_3189, func, target_7)
and func_8(vimage_3198, vstatus_3202, vn_3206, vmessage_3212, target_9, target_8)
and func_9(vn_3206, target_9)
and func_10(vimage_3198, vn_3206, vsvg_info_3209, vmessage_3212, target_10)
and func_11(vsvg_info_3209, target_11)
and func_12(vimage_3198, vn_3206, vmessage_3212, target_12)
and func_13(vimage_3198, target_13)
and func_14(vstatus_3202, vn_3206, vsvg_info_3209, vmessage_3212, target_14)
and func_15(vsvg_info_3209, vmessage_3212, target_15)
and func_16(vimage_3198, vsvg_info_3209, target_16)
and func_17(vfilename_3189, target_17)
and vfilename_3189.getType().hasName("char[4096]")
and voption_3192.getType().hasName("const char *")
and vimage_3198.getType().hasName("Image *")
and vstatus_3202.getType().hasName("int")
and vn_3206.getType().hasName("ssize_t")
and vsvg_info_3209.getType().hasName("SVGInfo *")
and vmessage_3212.getType().hasName("unsigned char[4096]")
and vimage_info_3186.getType().hasName("const ImageInfo *")
and vfilename_3189.getParentScope+() = func
and voption_3192.getParentScope+() = func
and vimage_3198.getParentScope+() = func
and vstatus_3202.getParentScope+() = func
and vn_3206.getParentScope+() = func
and vsvg_info_3209.getParentScope+() = func
and vmessage_3212.getParentScope+() = func
and vimage_info_3186.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
