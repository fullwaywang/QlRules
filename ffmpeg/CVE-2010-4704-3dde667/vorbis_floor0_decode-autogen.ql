/**
 * @name ffmpeg-3dde66752d59dfdd0f3727efd66e7202b3c75078-vorbis_floor0_decode
 * @id cpp/ffmpeg/3dde66752d59dfdd0f3727efd66e7202b3c75078/vorbis-floor0-decode
 * @description ffmpeg-3dde66752d59dfdd0f3727efd66e7202b3c75078-libavcodec/vorbis_dec.c-vorbis_floor0_decode CVE-2010-4704
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcodebook_1032, RelationalOperation target_1, ExprStmt target_2, ValueFieldAccess target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="codevectors"
		and target_0.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcodebook_1032
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(8)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget().getType().hasName("uint_fast32_t")
		and target_1.getLesserOperand().(Literal).getValue()="0"
}

predicate func_2(Variable vcodebook_1032, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcodebook_1032
		and target_2.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="codebooks"
		and target_2.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("vorbis_context *")
		and target_2.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="book_list"
		and target_2.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("vorbis_floor0 *")
		and target_2.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("uint_fast32_t")
}

predicate func_3(Variable vcodebook_1032, ValueFieldAccess target_3) {
		target_3.getTarget().getName()="vlc"
		and target_3.getQualifier().(VariableAccess).getTarget()=vcodebook_1032
}

from Function func, Variable vcodebook_1032, RelationalOperation target_1, ExprStmt target_2, ValueFieldAccess target_3
where
not func_0(vcodebook_1032, target_1, target_2, target_3)
and func_1(target_1)
and func_2(vcodebook_1032, target_2)
and func_3(vcodebook_1032, target_3)
and vcodebook_1032.getType().hasName("vorbis_codebook")
and vcodebook_1032.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
