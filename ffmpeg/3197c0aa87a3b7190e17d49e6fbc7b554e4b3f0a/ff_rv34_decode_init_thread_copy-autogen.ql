/**
 * @name ffmpeg-3197c0aa87a3b7190e17d49e6fbc7b554e4b3f0a-ff_rv34_decode_init_thread_copy
 * @id cpp/ffmpeg/3197c0aa87a3b7190e17d49e6fbc7b554e4b3f0a/ff-rv34-decode-init-thread-copy
 * @description ffmpeg-3197c0aa87a3b7190e17d49e6fbc7b554e4b3f0a-libavcodec/rv34.c-ff_rv34_decode_init_thread_copy CVE-2015-6826
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vr_1531, PointerFieldAccess target_5, ExprStmt target_6) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cbp_chroma"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_1531
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vr_1531, PointerFieldAccess target_5) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cbp_luma"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_1531
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5)
}

predicate func_2(Variable vr_1531, PointerFieldAccess target_5) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="deblock_coefs"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_1531
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5)
}

predicate func_3(Variable vr_1531, PointerFieldAccess target_5) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="intra_types_hist"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_1531
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5)
}

predicate func_4(Variable vr_1531, PointerFieldAccess target_5, AddressOfExpr target_7) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mb_type"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_1531
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(PointerFieldAccess target_5) {
		target_5.getTarget().getName()="is_copy"
		and target_5.getQualifier().(PointerFieldAccess).getTarget().getName()="internal"
}

predicate func_6(Variable vr_1531, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tmp_b_block_base"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_1531
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_7(Variable vr_1531, AddressOfExpr target_7) {
		target_7.getOperand().(PointerFieldAccess).getTarget().getName()="s"
		and target_7.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_1531
}

from Function func, Variable vr_1531, PointerFieldAccess target_5, ExprStmt target_6, AddressOfExpr target_7
where
not func_0(vr_1531, target_5, target_6)
and not func_1(vr_1531, target_5)
and not func_2(vr_1531, target_5)
and not func_3(vr_1531, target_5)
and not func_4(vr_1531, target_5, target_7)
and func_5(target_5)
and func_6(vr_1531, target_6)
and func_7(vr_1531, target_7)
and vr_1531.getType().hasName("RV34DecContext *")
and vr_1531.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
