/**
 * @name ghostscript-027c546e0dd11e0526f1780a7f3c2c66acffe209-image_render_color_thresh
 * @id cpp/ghostscript/027c546e0dd11e0526f1780a7f3c2c66acffe209/image-render-color-thresh
 * @description ghostscript-027c546e0dd11e0526f1780a7f3c2c66acffe209-base/gxicolor.c-image_render_color_thresh CVE-2020-16304
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdda_ht_638, DoStmt target_0) {
		target_0.getCondition().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(ValueFieldAccess).getTarget().getName()="R"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="state"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignSubExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdda_ht_638
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(ValueFieldAccess).getTarget().getName()="dR"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="step"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignSubExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdda_ht_638
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="R"
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="state"
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdda_ht_638
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getTarget().getName()="Q"
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(ValueFieldAccess).getTarget().getName()="R"
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(ValueFieldAccess).getTarget().getName()="N"
		and target_0.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(ValueFieldAccess).getTarget().getName()="Q"
		and target_0.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="state"
		and target_0.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdda_ht_638
		and target_0.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(ValueFieldAccess).getTarget().getName()="dQ"
		and target_0.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="step"
		and target_0.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdda_ht_638
}

predicate func_1(Variable vdda_ht_638, Variable vxn_639, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vxn_639
		and target_1.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="Q"
		and target_1.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="state"
		and target_1.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdda_ht_638
		and target_1.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getValue()="128"
		and target_1.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
}

predicate func_2(Variable vi_629, ExprStmt target_2) {
		target_2.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_629
}

predicate func_3(Variable vdevc_contone_623, Variable vpsrc_plane_624, Variable vposition_629, Variable vi_629, Variable vj_629, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdevc_contone_623
		and target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_629
		and target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vposition_629
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpsrc_plane_624
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_629
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_629
}

predicate func_4(Variable vposition_629, ExprStmt target_4) {
		target_4.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vposition_629
		and target_4.getExpr().(AssignSubExpr).getRValue().(MulExpr).getValue()="64"
}

predicate func_5(Variable vpenum_618, Variable vposition_629, ValueFieldAccess target_9, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vposition_629
		and target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="curr_pos"
		and target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ht_landscape"
		and target_5.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpenum_618
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

predicate func_6(Variable vdevc_contone_623, Variable vposition_629, Variable vk_629, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdevc_contone_623
		and target_6.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vk_629
		and target_6.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdevc_contone_623
		and target_6.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vk_629
		and target_6.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vposition_629
}

predicate func_7(Variable vdevc_contone_623, Variable vpsrc_plane_624, Variable vposition_629, Variable vi_629, Variable vj_629, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdevc_contone_623
		and target_7.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_629
		and target_7.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vposition_629
		and target_7.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpsrc_plane_624
		and target_7.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_629
		and target_7.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_629
}

predicate func_8(Variable vposition_629, ExprStmt target_8) {
		target_8.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vposition_629
		and target_8.getExpr().(AssignSubExpr).getRValue().(MulExpr).getValue()="64"
}

predicate func_9(Variable vpenum_618, ValueFieldAccess target_9) {
		target_9.getTarget().getName()="flipy"
		and target_9.getQualifier().(PointerFieldAccess).getTarget().getName()="ht_landscape"
		and target_9.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpenum_618
}

from Function func, Variable vpenum_618, Variable vdevc_contone_623, Variable vpsrc_plane_624, Variable vposition_629, Variable vi_629, Variable vj_629, Variable vk_629, Variable vdda_ht_638, Variable vxn_639, DoStmt target_0, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, ValueFieldAccess target_9
where
func_0(vdda_ht_638, target_0)
and func_1(vdda_ht_638, vxn_639, target_1)
and func_2(vi_629, target_2)
and func_3(vdevc_contone_623, vpsrc_plane_624, vposition_629, vi_629, vj_629, target_3)
and func_4(vposition_629, target_4)
and func_5(vpenum_618, vposition_629, target_9, target_5)
and func_6(vdevc_contone_623, vposition_629, vk_629, target_6)
and func_7(vdevc_contone_623, vpsrc_plane_624, vposition_629, vi_629, vj_629, target_7)
and func_8(vposition_629, target_8)
and func_9(vpenum_618, target_9)
and vpenum_618.getType().hasName("gx_image_enum *")
and vdevc_contone_623.getType().hasName("byte *[64]")
and vpsrc_plane_624.getType().hasName("byte *[64]")
and vposition_629.getType().hasName("int")
and vi_629.getType().hasName("int")
and vj_629.getType().hasName("int")
and vk_629.getType().hasName("int")
and vdda_ht_638.getType().hasName("gx_dda_fixed")
and vxn_639.getType().hasName("int")
and vpenum_618.(LocalVariable).getFunction() = func
and vdevc_contone_623.(LocalVariable).getFunction() = func
and vpsrc_plane_624.(LocalVariable).getFunction() = func
and vposition_629.(LocalVariable).getFunction() = func
and vi_629.(LocalVariable).getFunction() = func
and vj_629.(LocalVariable).getFunction() = func
and vk_629.(LocalVariable).getFunction() = func
and vdda_ht_638.(LocalVariable).getFunction() = func
and vxn_639.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
