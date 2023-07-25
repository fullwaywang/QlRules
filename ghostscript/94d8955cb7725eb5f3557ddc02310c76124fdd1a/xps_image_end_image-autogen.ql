/**
 * @name ghostscript-94d8955cb7725eb5f3557ddc02310c76124fdd1a-xps_image_end_image
 * @id cpp/ghostscript/94d8955cb7725eb5f3557ddc02310c76124fdd1a/xps-image-end-image
 * @description ghostscript-94d8955cb7725eb5f3557ddc02310c76124fdd1a-devices/vector/gdevxps.c-xps_image_end_image CVE-2020-16303
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpie_2196, Function func, IfStmt target_0) {
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pcs"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(DoStmt).getCondition().(Literal).getValue()="0"
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="pcs"
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

/*predicate func_1(Variable vpie_2196, IfStmt target_1) {
		target_1.getCondition().(PointerFieldAccess).getTarget().getName()="pcs"
		and target_1.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_1.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ref_count"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="ref_count"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rc"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pcs"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pcs"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse().(DoStmt).getCondition().(Literal).getValue()="0"
}

*/
/*predicate func_2(PointerFieldAccess target_17, Function func, DoStmt target_2) {
		target_2.getCondition().(Literal).getValue()="0"
		and target_2.getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_2.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ref_count"
		and target_2.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rc"
		and target_2.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pcs"
		and target_2.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
		and target_2.getEnclosingFunction() = func
}

*/
/*predicate func_3(Function func, DoStmt target_3) {
		target_3.getCondition().(Literal).getValue()="0"
		and target_3.getEnclosingFunction() = func
}

*/
/*predicate func_4(Variable vpie_2196, ExprStmt target_4) {
		target_4.getExpr().(AssignAddExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ref_count"
		and target_4.getExpr().(AssignAddExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rc"
		and target_4.getExpr().(AssignAddExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pcs"
		and target_4.getExpr().(AssignAddExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_4.getExpr().(AssignAddExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
}

*/
/*predicate func_5(Variable vpie_2196, PointerFieldAccess target_17, IfStmt target_5) {
		target_5.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="ref_count"
		and target_5.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rc"
		and target_5.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pcs"
		and target_5.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_5.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_5.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_5.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="free"
		and target_5.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="memory"
		and target_5.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="pcs"
		and target_5.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(2).(StringLiteral).getValue()="xps_image_end_image (pcs)"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pcs"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_5.getElse().(DoStmt).getCondition().(Literal).getValue()="0"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
}

*/
/*predicate func_6(Variable vpie_2196, NotExpr target_18, DoStmt target_6) {
		target_6.getCondition().(Literal).getValue()="0"
		and target_6.getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="free"
		and target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rc"
		and target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pcs"
		and target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="memory"
		and target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rc"
		and target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pcs"
		and target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="pcs"
		and target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(2).(StringLiteral).getValue()="xps_image_end_image (pcs)"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
}

*/
/*predicate func_7(Function func, DoStmt target_7) {
		target_7.getCondition().(Literal).getValue()="0"
		and target_7.getEnclosingFunction() = func
}

*/
/*predicate func_8(Variable vpie_2196, ExprStmt target_8) {
		target_8.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="free"
		and target_8.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rc"
		and target_8.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pcs"
		and target_8.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_8.getExpr().(VariableCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="memory"
		and target_8.getExpr().(VariableCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rc"
		and target_8.getExpr().(VariableCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pcs"
		and target_8.getExpr().(VariableCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_8.getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="pcs"
		and target_8.getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_8.getExpr().(VariableCall).getArgument(2).(StringLiteral).getValue()="xps_image_end_image (pcs)"
}

*/
/*predicate func_9(Variable vpie_2196, NotExpr target_18, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pcs"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_9.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
}

*/
predicate func_10(Variable vpie_2196, Function func, IfStmt target_10) {
		target_10.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="buffer"
		and target_10.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_10.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_10.getThen().(DoStmt).getCondition().(Literal).getValue()="0"
		and target_10.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="memory"
		and target_10.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_10.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10
}

/*predicate func_11(Variable vpie_2196, IfStmt target_11) {
		target_11.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="memory"
		and target_11.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_11.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="free_object"
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="memory"
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="buffer"
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(2).(StringLiteral).getValue()="xps_image_end_image"
}

*/
/*predicate func_12(Variable vpie_2196, EqualityOperation target_19, ExprStmt target_12) {
		target_12.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="free_object"
		and target_12.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_12.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_12.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_12.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="memory"
		and target_12.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_12.getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="buffer"
		and target_12.getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_12.getExpr().(VariableCall).getArgument(2).(StringLiteral).getValue()="xps_image_end_image"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
}

*/
predicate func_13(Variable vpie_2196, Function func, IfStmt target_13) {
		target_13.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="devc_buffer"
		and target_13.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_13.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_13.getThen().(DoStmt).getCondition().(Literal).getValue()="0"
		and target_13.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="memory"
		and target_13.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_13.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_13
}

/*predicate func_14(Variable vpie_2196, IfStmt target_14) {
		target_14.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="memory"
		and target_14.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_14.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="free_object"
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="memory"
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="devc_buffer"
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(2).(StringLiteral).getValue()="xps_image_end_image"
}

*/
/*predicate func_15(Variable vpie_2196, EqualityOperation target_20, ExprStmt target_15) {
		target_15.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="free_object"
		and target_15.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_15.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_15.getExpr().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_15.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="memory"
		and target_15.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_15.getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="devc_buffer"
		and target_15.getExpr().(VariableCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_15.getExpr().(VariableCall).getArgument(2).(StringLiteral).getValue()="xps_image_end_image"
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_20
}

*/
predicate func_16(Variable vpie_2196, Function func, IfStmt target_16) {
		target_16.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="icc_link"
		and target_16.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_16.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_16.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("gsicc_release_link")
		and target_16.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="icc_link"
		and target_16.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_16
}

predicate func_17(Variable vpie_2196, PointerFieldAccess target_17) {
		target_17.getTarget().getName()="pcs"
		and target_17.getQualifier().(VariableAccess).getTarget()=vpie_2196
}

predicate func_18(NotExpr target_18) {
		target_18.getOperand() instanceof ValueFieldAccess
}

predicate func_19(Variable vpie_2196, EqualityOperation target_19) {
		target_19.getAnOperand().(PointerFieldAccess).getTarget().getName()="memory"
		and target_19.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_19.getAnOperand() instanceof Literal
}

predicate func_20(Variable vpie_2196, EqualityOperation target_20) {
		target_20.getAnOperand().(PointerFieldAccess).getTarget().getName()="memory"
		and target_20.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpie_2196
		and target_20.getAnOperand() instanceof Literal
}

from Function func, Variable vpie_2196, IfStmt target_0, IfStmt target_10, IfStmt target_13, IfStmt target_16, PointerFieldAccess target_17, NotExpr target_18, EqualityOperation target_19, EqualityOperation target_20
where
func_0(vpie_2196, func, target_0)
and func_10(vpie_2196, func, target_10)
and func_13(vpie_2196, func, target_13)
and func_16(vpie_2196, func, target_16)
and func_17(vpie_2196, target_17)
and func_18(target_18)
and func_19(vpie_2196, target_19)
and func_20(vpie_2196, target_20)
and vpie_2196.getType().hasName("xps_image_enum_t *")
and vpie_2196.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
