/**
 * @name expat-be4b1c06daba1849b8ff5e00bae5caf47f6c39fd-doContent
 * @id cpp/expat/be4b1c06daba1849b8ff5e00bae5caf47f6c39fd/doContent
 * @description expat-be4b1c06daba1849b8ff5e00bae5caf47f6c39fd-expat/lib/xmlparse.c-doContent CVE-2016-0718
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_14, Function func) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("XML_Convert_Result")
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("XML_Convert_Result")
		and target_0.getParent().(IfStmt).getThen()=target_14
		and target_0.getEnclosingFunction() = func)
}

predicate func_5(BreakStmt target_15, Function func) {
	exists(LogicalOrExpr target_5 |
		target_5.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("XML_Convert_Result")
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("XML_Convert_Result")
		and target_5.getParent().(IfStmt).getThen()=target_15
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Variable vtoPtr_2436, Variable vrawNameEnd_2461, Variable vfromPtr_2462, Parameter venc_2282, Variable vtag_2434, VariableCall target_6) {
		target_6.getExpr().(PointerFieldAccess).getTarget().getName()="utf8Convert"
		and target_6.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venc_2282
		and target_6.getArgument(0).(VariableAccess).getTarget()=venc_2282
		and target_6.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vfromPtr_2462
		and target_6.getArgument(2).(VariableAccess).getTarget()=vrawNameEnd_2461
		and target_6.getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtoPtr_2436
		and target_6.getArgument(4).(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="bufEnd"
		and target_6.getArgument(4).(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtag_2434
		and target_6.getArgument(4).(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
}

predicate func_7(Parameter venc_2282, Parameter vs_2283, Variable vnext_2304, Parameter vparser_2280, Variable vdataPtr_2691, VariableCall target_7) {
		target_7.getExpr().(PointerFieldAccess).getTarget().getName()="utf8Convert"
		and target_7.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venc_2282
		and target_7.getArgument(0).(VariableAccess).getTarget()=venc_2282
		and target_7.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vs_2283
		and target_7.getArgument(2).(VariableAccess).getTarget()=vnext_2304
		and target_7.getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vdataPtr_2691
		and target_7.getArgument(4).(PointerFieldAccess).getTarget().getName()="m_dataBufEnd"
		and target_7.getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_2280
}

predicate func_8(Function func, ExprStmt target_8) {
		target_8.getExpr() instanceof VariableCall
		and target_8.getEnclosingFunction() = func
}

/*predicate func_9(Variable vrawNameEnd_2461, Variable vfromPtr_2462, BlockStmt target_14, VariableAccess target_9) {
		target_9.getTarget()=vfromPtr_2462
		and target_9.getParent().(EQExpr).getAnOperand().(VariableAccess).getTarget()=vrawNameEnd_2461
		and target_9.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_14
}

*/
/*predicate func_10(Variable vrawNameEnd_2461, Variable vfromPtr_2462, BlockStmt target_14, ExprStmt target_8, AddressOfExpr target_16, VariableAccess target_10) {
		target_10.getTarget()=vrawNameEnd_2461
		and target_10.getParent().(EQExpr).getAnOperand().(VariableAccess).getTarget()=vfromPtr_2462
		and target_10.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_14
		and target_16.getOperand().(VariableAccess).getLocation().isBefore(target_10.getParent().(EQExpr).getAnOperand().(VariableAccess).getLocation())
}

*/
predicate func_11(Function func, ExprStmt target_11) {
		target_11.getExpr() instanceof VariableCall
		and target_11.getEnclosingFunction() = func
}

/*predicate func_12(Parameter vs_2283, Variable vnext_2304, BreakStmt target_15, ExprStmt target_17, ExprStmt target_18, ExprStmt target_11, PointerArithmeticOperation target_19, VariableAccess target_12) {
		target_12.getTarget()=vs_2283
		and target_12.getParent().(EQExpr).getAnOperand().(VariableAccess).getTarget()=vnext_2304
		and target_12.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_15
		and target_17.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_12.getLocation())
		and target_12.getLocation().isBefore(target_18.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_12.getParent().(EQExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_19.getLeftOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_13(Parameter vs_2283, Variable vnext_2304, BreakStmt target_15, ExprStmt target_17, ExprStmt target_18, ExprStmt target_11, PointerArithmeticOperation target_19, VariableAccess target_13) {
		target_13.getTarget()=vnext_2304
		and target_13.getParent().(EQExpr).getAnOperand().(VariableAccess).getTarget()=vs_2283
		and target_13.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_15
		and target_17.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_13.getParent().(EQExpr).getAnOperand().(VariableAccess).getLocation())
		and target_13.getParent().(EQExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_13.getLocation().isBefore(target_19.getLeftOperand().(VariableAccess).getLocation())
}

*/
predicate func_14(Variable vtag_2434, BlockStmt target_14) {
		target_14.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="strLen"
		and target_14.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="name"
		and target_14.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtag_2434
		and target_14.getStmt(1).(BreakStmt).toString() = "break;"
}

predicate func_15(BreakStmt target_15) {
		target_15.toString() = "break;"
}

predicate func_16(Variable vfromPtr_2462, AddressOfExpr target_16) {
		target_16.getOperand().(VariableAccess).getTarget()=vfromPtr_2462
}

predicate func_17(Parameter vs_2283, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vs_2283
}

predicate func_18(Parameter vs_2283, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vs_2283
}

predicate func_19(Parameter vs_2283, Variable vnext_2304, PointerArithmeticOperation target_19) {
		target_19.getLeftOperand().(VariableAccess).getTarget()=vnext_2304
		and target_19.getRightOperand().(VariableAccess).getTarget()=vs_2283
}

from Function func, Variable vtoPtr_2436, Variable vrawNameEnd_2461, Variable vfromPtr_2462, Parameter venc_2282, Parameter vs_2283, Variable vnext_2304, Variable vtag_2434, Parameter vparser_2280, Variable vdataPtr_2691, VariableCall target_6, VariableCall target_7, ExprStmt target_8, ExprStmt target_11, BlockStmt target_14, BreakStmt target_15, AddressOfExpr target_16, ExprStmt target_17, ExprStmt target_18, PointerArithmeticOperation target_19
where
not func_0(target_14, func)
and not func_5(target_15, func)
and func_6(vtoPtr_2436, vrawNameEnd_2461, vfromPtr_2462, venc_2282, vtag_2434, target_6)
and func_7(venc_2282, vs_2283, vnext_2304, vparser_2280, vdataPtr_2691, target_7)
and func_8(func, target_8)
and func_11(func, target_11)
and func_14(vtag_2434, target_14)
and func_15(target_15)
and func_16(vfromPtr_2462, target_16)
and func_17(vs_2283, target_17)
and func_18(vs_2283, target_18)
and func_19(vs_2283, vnext_2304, target_19)
and vtoPtr_2436.getType().hasName("XML_Char *")
and vrawNameEnd_2461.getType().hasName("const char *")
and vfromPtr_2462.getType().hasName("const char *")
and venc_2282.getType().hasName("const ENCODING *")
and vs_2283.getType().hasName("const char *")
and vnext_2304.getType().hasName("const char *")
and vtag_2434.getType().hasName("TAG *")
and vparser_2280.getType().hasName("XML_Parser")
and vdataPtr_2691.getType().hasName("ICHAR *")
and vtoPtr_2436.getParentScope+() = func
and vrawNameEnd_2461.getParentScope+() = func
and vfromPtr_2462.getParentScope+() = func
and venc_2282.getParentScope+() = func
and vs_2283.getParentScope+() = func
and vnext_2304.getParentScope+() = func
and vtag_2434.getParentScope+() = func
and vparser_2280.getParentScope+() = func
and vdataPtr_2691.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
