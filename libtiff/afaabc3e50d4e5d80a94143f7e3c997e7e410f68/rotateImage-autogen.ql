/**
 * @name libtiff-afaabc3e50d4e5d80a94143f7e3c997e7e410f68-rotateImage
 * @id cpp/libtiff/afaabc3e50d4e5d80a94143f7e3c997e7e410f68/rotateImage
 * @description libtiff-afaabc3e50d4e5d80a94143f7e3c997e7e410f68-tools/tiffcrop.c-rotateImage CVE-2023-0795
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(VariableAccess target_12, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getType().hasName("int")
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(4) instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_12
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(VariableAccess target_12, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(VariableAccess).getType().hasName("int")
		and target_1.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(4) instanceof ExprStmt
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_12
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vimage_9622, Variable vlength_9629, VariableAccess target_12, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="width"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_9622
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlength_9629
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_12
}

predicate func_3(Parameter vimage_9622, Variable vwidth_9629, VariableAccess target_12, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_9622
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vwidth_9629
		and target_3.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_12
}

predicate func_4(Parameter vimage_9622, Variable vres_temp_9636, VariableAccess target_12, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vres_temp_9636
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="xres"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_9622
		and target_4.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_12
}

predicate func_5(Parameter vimage_9622, VariableAccess target_12, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="xres"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_9622
		and target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="yres"
		and target_5.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_9622
		and target_5.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_12
}

predicate func_6(Parameter vimage_9622, Variable vres_temp_9636, VariableAccess target_12, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="yres"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_9622
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vres_temp_9636
		and target_6.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_12
}

predicate func_7(Parameter vimage_9622, Variable vlength_9629, VariableAccess target_12, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="width"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_9622
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlength_9629
		and target_7.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_12
}

predicate func_8(Parameter vimage_9622, Variable vwidth_9629, VariableAccess target_12, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_9622
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vwidth_9629
		and target_8.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_12
}

predicate func_9(Parameter vimage_9622, Variable vres_temp_9636, VariableAccess target_12, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vres_temp_9636
		and target_9.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="xres"
		and target_9.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_9622
		and target_9.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_12
}

predicate func_10(Parameter vimage_9622, VariableAccess target_12, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="xres"
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_9622
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="yres"
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_9622
		and target_10.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_12
}

predicate func_11(Parameter vimage_9622, Variable vres_temp_9636, VariableAccess target_12, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="yres"
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_9622
		and target_11.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vres_temp_9636
		and target_11.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_12
}

predicate func_12(Parameter vrotation_9622, VariableAccess target_12) {
		target_12.getTarget()=vrotation_9622
}

from Function func, Parameter vrotation_9622, Parameter vimage_9622, Variable vwidth_9629, Variable vlength_9629, Variable vres_temp_9636, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11, VariableAccess target_12
where
not func_0(target_12, func)
and not func_1(target_12, func)
and func_2(vimage_9622, vlength_9629, target_12, target_2)
and func_3(vimage_9622, vwidth_9629, target_12, target_3)
and func_4(vimage_9622, vres_temp_9636, target_12, target_4)
and func_5(vimage_9622, target_12, target_5)
and func_6(vimage_9622, vres_temp_9636, target_12, target_6)
and func_7(vimage_9622, vlength_9629, target_12, target_7)
and func_8(vimage_9622, vwidth_9629, target_12, target_8)
and func_9(vimage_9622, vres_temp_9636, target_12, target_9)
and func_10(vimage_9622, target_12, target_10)
and func_11(vimage_9622, vres_temp_9636, target_12, target_11)
and func_12(vrotation_9622, target_12)
and vrotation_9622.getType().hasName("uint16_t")
and vimage_9622.getType().hasName("image_data *")
and vwidth_9629.getType().hasName("uint32_t")
and vlength_9629.getType().hasName("uint32_t")
and vres_temp_9636.getType().hasName("float")
and vrotation_9622.getFunction() = func
and vimage_9622.getFunction() = func
and vwidth_9629.(LocalVariable).getFunction() = func
and vlength_9629.(LocalVariable).getFunction() = func
and vres_temp_9636.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
