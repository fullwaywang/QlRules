/**
 * @name libxml2-6a36fbe3b3e001a8a840b5c1fdd81cefc9947f0d-xmlParseAttValueComplex
 * @id cpp/libxml2/6a36fbe3b3e001a8a840b5c1fdd81cefc9947f0d/xmlParseAttValueComplex
 * @description libxml2-6a36fbe3b3e001a8a840b5c1fdd81cefc9947f0d-parser.c-xmlParseAttValueComplex CVE-2012-5134
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_3894, FunctionCall target_0) {
		target_0.getTarget().hasName("xmlNextChar__internal_alias")
		and not target_0.getTarget().hasName("xmlNextChar")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vctxt_3894
}

predicate func_1(Parameter vctxt_3894, FunctionCall target_1) {
		target_1.getTarget().hasName("xmlNextChar__internal_alias")
		and not target_1.getTarget().hasName("xmlNextChar")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vctxt_3894
}

predicate func_2(Parameter vctxt_3894, Variable vc_3900, Variable vl_3900, FunctionCall target_2) {
		target_2.getTarget().hasName("xmlCurrentChar__internal_alias")
		and not target_2.getTarget().hasName("xmlCurrentChar")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vctxt_3894
		and target_2.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl_3900
		and target_2.getParent().(AssignExpr).getRValue() = target_2
		and target_2.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_3900
}

predicate func_3(Parameter vctxt_3894, FunctionCall target_3) {
		target_3.getTarget().hasName("xmlParseCharRef__internal_alias")
		and not target_3.getTarget().hasName("xmlParseCharRef")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vctxt_3894
}

predicate func_4(Variable vbuf_3896, Variable vlen_3898, Variable vval_3945, FunctionCall target_4) {
		target_4.getTarget().hasName("xmlCopyChar__internal_alias")
		and not target_4.getTarget().hasName("xmlCopyChar")
		and target_4.getArgument(0).(Literal).getValue()="0"
		and target_4.getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_3896
		and target_4.getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlen_3898
		and target_4.getArgument(2).(VariableAccess).getTarget()=vval_3945
		and target_4.getParent().(AssignAddExpr).getRValue() = target_4
		and target_4.getParent().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen_3898
}

predicate func_5(Parameter vctxt_3894, Variable vent_3902, FunctionCall target_5) {
		target_5.getTarget().hasName("xmlParseEntityRef__internal_alias")
		and not target_5.getTarget().hasName("xmlParseEntityRef")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vctxt_3894
		and target_5.getParent().(AssignExpr).getRValue() = target_5
		and target_5.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vent_3902
}

predicate func_6(Parameter vctxt_3894, Variable vent_3902, FunctionCall target_6) {
		target_6.getTarget().hasName("xmlStringDecodeEntities__internal_alias")
		and not target_6.getTarget().hasName("xmlStringDecodeEntities")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vctxt_3894
		and target_6.getArgument(1).(PointerFieldAccess).getTarget().getName()="content"
		and target_6.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_3902
		and target_6.getArgument(2).(Literal).getValue()="1"
		and target_6.getArgument(3).(Literal).getValue()="0"
		and target_6.getArgument(4).(Literal).getValue()="0"
		and target_6.getArgument(5).(Literal).getValue()="0"
		and target_6.getParent().(AssignExpr).getRValue() = target_6
		and target_6.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("xmlChar *")
}

predicate func_7(Variable vent_3902, FunctionCall target_7) {
		target_7.getTarget().hasName("xmlStrlen__internal_alias")
		and not target_7.getTarget().hasName("xmlStrlen")
		and target_7.getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_7.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_3902
}

predicate func_8(Parameter vctxt_3894, Variable vent_3902, FunctionCall target_8) {
		target_8.getTarget().hasName("xmlStringDecodeEntities__internal_alias")
		and not target_8.getTarget().hasName("xmlStringDecodeEntities")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vctxt_3894
		and target_8.getArgument(1).(PointerFieldAccess).getTarget().getName()="content"
		and target_8.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_3902
		and target_8.getArgument(2).(Literal).getValue()="1"
		and target_8.getArgument(3).(Literal).getValue()="0"
		and target_8.getArgument(4).(Literal).getValue()="0"
		and target_8.getArgument(5).(Literal).getValue()="0"
		and target_8.getParent().(AssignExpr).getRValue() = target_8
		and target_8.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("xmlChar *")
}

predicate func_9(Variable vbuf_3896, Variable vlen_3898, FunctionCall target_9) {
		target_9.getTarget().hasName("xmlCopyCharMultiByte__internal_alias")
		and not target_9.getTarget().hasName("xmlCopyCharMultiByte")
		and target_9.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_3896
		and target_9.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlen_3898
		and target_9.getArgument(1).(Literal).getValue()="32"
		and target_9.getParent().(AssignAddExpr).getRValue() = target_9
		and target_9.getParent().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen_3898
}

predicate func_10(Variable vbuf_3896, Variable vlen_3898, Variable vc_3900, FunctionCall target_10) {
		target_10.getTarget().hasName("xmlCopyCharMultiByte__internal_alias")
		and not target_10.getTarget().hasName("xmlCopyCharMultiByte")
		and target_10.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_3896
		and target_10.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlen_3898
		and target_10.getArgument(1).(VariableAccess).getTarget()=vc_3900
		and target_10.getParent().(AssignAddExpr).getRValue() = target_10
		and target_10.getParent().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen_3898
}

predicate func_11(Parameter vctxt_3894, FunctionCall target_11) {
		target_11.getTarget().hasName("xmlParserHandlePEReference__internal_alias")
		and not target_11.getTarget().hasName("xmlParserHandlePEReference")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vctxt_3894
}

predicate func_12(Parameter vctxt_3894, Variable vc_3900, Variable vl_3900, FunctionCall target_12) {
		target_12.getTarget().hasName("xmlCurrentChar__internal_alias")
		and not target_12.getTarget().hasName("xmlCurrentChar")
		and target_12.getArgument(0).(VariableAccess).getTarget()=vctxt_3894
		and target_12.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl_3900
		and target_12.getParent().(AssignExpr).getRValue() = target_12
		and target_12.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_3900
}

predicate func_13(Parameter vctxt_3894, FunctionCall target_13) {
		target_13.getTarget().hasName("xmlNextChar__internal_alias")
		and not target_13.getTarget().hasName("xmlNextChar")
		and target_13.getArgument(0).(VariableAccess).getTarget()=vctxt_3894
}

predicate func_14(Parameter vctxt_3894, FunctionCall target_14) {
		target_14.getTarget().hasName("xmlErrMemory__internal_alias")
		and not target_14.getTarget().hasName("xmlErrMemory")
		and target_14.getArgument(0).(VariableAccess).getTarget()=vctxt_3894
		and target_14.getArgument(1).(Literal).getValue()="0"
}

predicate func_15(Variable vlen_3898, RelationalOperation target_17, EqualityOperation target_16) {
	exists(LogicalAndExpr target_15 |
		target_15.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_3898
		and target_15.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_15.getAnOperand() instanceof EqualityOperation
		and target_17.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_15.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_15.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_16.getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_16(Variable vbuf_3896, Variable vlen_3898, EqualityOperation target_16) {
		target_16.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_3896
		and target_16.getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_3898
		and target_16.getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_16.getAnOperand().(HexLiteral).getValue()="32"
}

predicate func_17(Variable vlen_3898, RelationalOperation target_17) {
		 (target_17 instanceof GTExpr or target_17 instanceof LTExpr)
		and target_17.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_3898
		and target_17.getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="10"
		and target_17.getLesserOperand().(VariableAccess).getTarget().getType().hasName("size_t")
}

from Function func, Parameter vctxt_3894, Variable vbuf_3896, Variable vlen_3898, Variable vc_3900, Variable vl_3900, Variable vent_3902, Variable vval_3945, FunctionCall target_0, FunctionCall target_1, FunctionCall target_2, FunctionCall target_3, FunctionCall target_4, FunctionCall target_5, FunctionCall target_6, FunctionCall target_7, FunctionCall target_8, FunctionCall target_9, FunctionCall target_10, FunctionCall target_11, FunctionCall target_12, FunctionCall target_13, FunctionCall target_14, EqualityOperation target_16, RelationalOperation target_17
where
func_0(vctxt_3894, target_0)
and func_1(vctxt_3894, target_1)
and func_2(vctxt_3894, vc_3900, vl_3900, target_2)
and func_3(vctxt_3894, target_3)
and func_4(vbuf_3896, vlen_3898, vval_3945, target_4)
and func_5(vctxt_3894, vent_3902, target_5)
and func_6(vctxt_3894, vent_3902, target_6)
and func_7(vent_3902, target_7)
and func_8(vctxt_3894, vent_3902, target_8)
and func_9(vbuf_3896, vlen_3898, target_9)
and func_10(vbuf_3896, vlen_3898, vc_3900, target_10)
and func_11(vctxt_3894, target_11)
and func_12(vctxt_3894, vc_3900, vl_3900, target_12)
and func_13(vctxt_3894, target_13)
and func_14(vctxt_3894, target_14)
and not func_15(vlen_3898, target_17, target_16)
and func_16(vbuf_3896, vlen_3898, target_16)
and func_17(vlen_3898, target_17)
and vctxt_3894.getType().hasName("xmlParserCtxtPtr")
and vbuf_3896.getType().hasName("xmlChar *")
and vlen_3898.getType().hasName("size_t")
and vc_3900.getType().hasName("int")
and vl_3900.getType().hasName("int")
and vent_3902.getType().hasName("xmlEntityPtr")
and vval_3945.getType().hasName("int")
and vctxt_3894.getFunction() = func
and vbuf_3896.(LocalVariable).getFunction() = func
and vlen_3898.(LocalVariable).getFunction() = func
and vc_3900.(LocalVariable).getFunction() = func
and vl_3900.(LocalVariable).getFunction() = func
and vent_3902.(LocalVariable).getFunction() = func
and vval_3945.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
