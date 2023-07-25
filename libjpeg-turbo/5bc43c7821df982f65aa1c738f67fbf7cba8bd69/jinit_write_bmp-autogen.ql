/**
 * @name libjpeg-turbo-5bc43c7821df982f65aa1c738f67fbf7cba8bd69-jinit_write_bmp
 * @id cpp/libjpeg-turbo/5bc43c7821df982f65aa1c738f67fbf7cba8bd69/jinit-write-bmp
 * @description libjpeg-turbo-5bc43c7821df982f65aa1c738f67fbf7cba8bd69-wrbmp.c-jinit_write_bmp CVE-2017-15232
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, SizeofTypeOperator target_0) {
		target_0.getType() instanceof LongType
		and target_0.getValue()="80"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vdest_431, ExprStmt target_2, ExprStmt target_3, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="calc_buffer_dimensions"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pub"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_431
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_1)
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vdest_431, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="finish_output"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pub"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_431
}

predicate func_3(Variable vdest_431, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="is_os2"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdest_431
}

from Function func, Variable vdest_431, SizeofTypeOperator target_0, ExprStmt target_2, ExprStmt target_3
where
func_0(func, target_0)
and not func_1(vdest_431, target_2, target_3, func)
and func_2(vdest_431, target_2)
and func_3(vdest_431, target_3)
and vdest_431.getType().hasName("bmp_dest_ptr")
and vdest_431.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
