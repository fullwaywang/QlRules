/**
 * @name expat-9b4ce651b26557f16103c3a366c91934ecd439ab-build_model
 * @id cpp/expat/9b4ce651b26557f16103c3a366c91934ecd439ab/build-model
 * @description expat-9b4ce651b26557f16103c3a366c91934ecd439ab-expat/lib/xmlparse.c-build_model CVE-2022-25313
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

/*predicate func_0(Variable vret_7355, VariableAccess target_0) {
		target_0.getTarget()=vret_7355
		and target_0.getParent().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

*/
predicate func_1(Variable vret_7355, Variable vcpos_7356, VariableAccess target_1) {
		target_1.getTarget()=vcpos_7356
		and target_1.getParent().(AssignExpr).getLValue() = target_1
		and target_1.getParent().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vret_7355
		and target_1.getParent().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_2(Variable vcpos_7356, VariableAccess target_2) {
		target_2.getTarget()=vcpos_7356
}

predicate func_3(Variable vret_7355, ExprStmt target_13, ReturnStmt target_14) {
	exists(Initializer target_3 |
		target_3.getExpr().(VariableAccess).getTarget()=vret_7355
		and target_13.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_3.getExpr().(VariableAccess).getLocation())
		and target_3.getExpr().(VariableAccess).getLocation().isBefore(target_14.getExpr().(VariableAccess).getLocation()))
}

predicate func_4(Function func) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(PointerFieldAccess).getTarget().getName()="numchildren"
		and target_4.getLValue().(PointerFieldAccess).getQualifier().(PrefixDecrExpr).getOperand().(VariableAccess).getType().hasName("XML_Content *")
		and target_4.getRValue() instanceof Literal
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Variable vstr_7357, ExprStmt target_15, AddressOfExpr target_16, Function func) {
	exists(ForStmt target_5 |
		target_5.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("XML_Content *")
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("XML_Content *")
		and target_5.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("XML_Content *")
		and target_5.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="type"
		and target_5.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("XML_Content *")
		and target_5.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="type"
		and target_5.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="scaffold"
		and target_5.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("int")
		and target_5.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="quant"
		and target_5.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("XML_Content *")
		and target_5.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="quant"
		and target_5.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="scaffold"
		and target_5.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("int")
		and target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("XML_Content *")
		and target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="name"
		and target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vstr_7357
		and target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("const XML_Char *")
		and target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="name"
		and target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(3).(BlockStmt).getStmt(1).(LabelStmt).toString() = "label ...:"
		and target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="numchildren"
		and target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="children"
		and target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="name"
		and target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="numchildren"
		and target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="childcnt"
		and target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="children"
		and target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignPointerSubExpr).getLValue().(VariableAccess).getType().hasName("XML_Content *")
		and target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignPointerSubExpr).getRValue().(PointerFieldAccess).getTarget().getName()="numchildren"
		and target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getElse().(BlockStmt).getStmt(6).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getElse().(BlockStmt).getStmt(6).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="numchildren"
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_5)
		and target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_5.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_16.getOperand().(VariableAccess).getLocation()))
}

/*predicate func_6(Variable vdtd_7354) {
	exists(AssignExpr target_6 |
		target_6.getLValue().(PointerFieldAccess).getTarget().getName()="quant"
		and target_6.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("XML_Content *")
		and target_6.getRValue().(ValueFieldAccess).getTarget().getName()="quant"
		and target_6.getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="scaffold"
		and target_6.getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdtd_7354
		and target_6.getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("int"))
}

*/
/*predicate func_7(Function func) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="children"
		and target_7.getQualifier().(VariableAccess).getType().hasName("XML_Content *")
		and target_7.getEnclosingFunction() = func)
}

*/
predicate func_9(Variable vstr_7357, VariableAccess target_9) {
		target_9.getTarget()=vstr_7357
}

predicate func_11(Variable vret_7355, VariableAccess target_11) {
		target_11.getTarget()=vret_7355
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_12(Parameter vparser_7353, Variable vret_7355, Variable vcpos_7356, Variable vstr_7357, FunctionCall target_12) {
		target_12.getTarget().hasName("build_node")
		and target_12.getArgument(0).(VariableAccess).getTarget()=vparser_7353
		and target_12.getArgument(1) instanceof Literal
		and target_12.getArgument(2).(VariableAccess).getTarget()=vret_7355
		and target_12.getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcpos_7356
		and target_12.getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vstr_7357
}

predicate func_13(Variable vret_7355, Variable vcpos_7356, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcpos_7356
		and target_13.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vret_7355
		and target_13.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_14(Variable vret_7355, ReturnStmt target_14) {
		target_14.getExpr().(VariableAccess).getTarget()=vret_7355
}

predicate func_15(Variable vdtd_7354, Variable vret_7355, Variable vstr_7357, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstr_7357
		and target_15.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vret_7355
		and target_15.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="scaffCount"
		and target_15.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdtd_7354
}

predicate func_16(Variable vstr_7357, AddressOfExpr target_16) {
		target_16.getOperand().(VariableAccess).getTarget()=vstr_7357
}

from Function func, Parameter vparser_7353, Variable vdtd_7354, Variable vret_7355, Variable vcpos_7356, Variable vstr_7357, VariableAccess target_1, VariableAccess target_2, VariableAccess target_9, VariableAccess target_11, FunctionCall target_12, ExprStmt target_13, ReturnStmt target_14, ExprStmt target_15, AddressOfExpr target_16
where
func_1(vret_7355, vcpos_7356, target_1)
and func_2(vcpos_7356, target_2)
and not func_3(vret_7355, target_13, target_14)
and not func_4(func)
and not func_5(vstr_7357, target_15, target_16, func)
and func_9(vstr_7357, target_9)
and func_11(vret_7355, target_11)
and func_12(vparser_7353, vret_7355, vcpos_7356, vstr_7357, target_12)
and func_13(vret_7355, vcpos_7356, target_13)
and func_14(vret_7355, target_14)
and func_15(vdtd_7354, vret_7355, vstr_7357, target_15)
and func_16(vstr_7357, target_16)
and vparser_7353.getType().hasName("XML_Parser")
and vdtd_7354.getType().hasName("DTD *const")
and vret_7355.getType().hasName("XML_Content *")
and vcpos_7356.getType().hasName("XML_Content *")
and vstr_7357.getType().hasName("XML_Char *")
and vparser_7353.getParentScope+() = func
and vdtd_7354.getParentScope+() = func
and vret_7355.getParentScope+() = func
and vcpos_7356.getParentScope+() = func
and vstr_7357.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
