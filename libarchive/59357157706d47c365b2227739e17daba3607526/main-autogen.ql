/**
 * @name libarchive-59357157706d47c365b2227739e17daba3607526-main
 * @id cpp/libarchive/59357157706d47c365b2227739e17daba3607526/main
 * @description libarchive-59357157706d47c365b2227739e17daba3607526-cpio/cpio.c-main CVE-2015-2304
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcpio_135, ExprStmt target_2, ExprStmt target_3, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="extract_flags"
		and target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcpio_135
		and target_0.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="65536"
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_0)
		and target_2.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcpio_135, VariableAccess target_4, ExprStmt target_5, ExprStmt target_6) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getTarget().getName()="extract_flags"
		and target_1.getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcpio_135
		and target_1.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getValue()="-65537"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_4
		and target_5.getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vcpio_135, ExprStmt target_2) {
		target_2.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="extract_flags"
		and target_2.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcpio_135
		and target_2.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="512"
}

predicate func_3(Variable vcpio_135, ExprStmt target_3) {
		target_3.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="extract_flags"
		and target_3.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcpio_135
		and target_3.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="2"
}

predicate func_4(Variable vopt_138, VariableAccess target_4) {
		target_4.getTarget()=vopt_138
}

predicate func_5(Variable vcpio_135, ExprStmt target_5) {
		target_5.getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getTarget().getName()="extract_flags"
		and target_5.getExpr().(AssignAndExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcpio_135
		and target_5.getExpr().(AssignAndExpr).getRValue().(ComplementExpr).getValue()="-513"
}

predicate func_6(Variable vcpio_135, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="option_follow_links"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcpio_135
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

from Function func, Variable vcpio_135, Variable vopt_138, ExprStmt target_2, ExprStmt target_3, VariableAccess target_4, ExprStmt target_5, ExprStmt target_6
where
not func_0(vcpio_135, target_2, target_3, func)
and not func_1(vcpio_135, target_4, target_5, target_6)
and func_2(vcpio_135, target_2)
and func_3(vcpio_135, target_3)
and func_4(vopt_138, target_4)
and func_5(vcpio_135, target_5)
and func_6(vcpio_135, target_6)
and vcpio_135.getType().hasName("cpio *")
and vopt_138.getType().hasName("int")
and vcpio_135.getParentScope+() = func
and vopt_138.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
