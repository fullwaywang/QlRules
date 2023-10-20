/**
 * @name libtiff-662f74445b2fea2eeb759c6524661118aef567ca-NeXTDecode
 * @id cpp/libtiff/662f74445b2fea2eeb759c6524661118aef567ca/NeXTDecode
 * @description libtiff-662f74445b2fea2eeb759c6524661118aef567ca-libtiff/tif_next.c-NeXTDecode CVE-2014-9330
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vimagewidth_104, Parameter vtif_49, LogicalAndExpr target_1, ValueFieldAccess target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tif_flags"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_49
		and target_0.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1024"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vimagewidth_104
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="td_tilewidth"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_49
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vimagewidth_104, LogicalAndExpr target_1) {
		target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vimagewidth_104
}

predicate func_2(Parameter vtif_49, ValueFieldAccess target_2) {
		target_2.getTarget().getName()="td_imagewidth"
		and target_2.getQualifier().(PointerFieldAccess).getTarget().getName()="tif_dir"
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_49
}

predicate func_3(Parameter vtif_49, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tif_rawcp"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_49
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("unsigned char *")
}

from Function func, Variable vimagewidth_104, Parameter vtif_49, LogicalAndExpr target_1, ValueFieldAccess target_2, ExprStmt target_3
where
not func_0(vimagewidth_104, vtif_49, target_1, target_2, target_3)
and func_1(vimagewidth_104, target_1)
and func_2(vtif_49, target_2)
and func_3(vtif_49, target_3)
and vimagewidth_104.getType().hasName("uint32")
and vtif_49.getType().hasName("TIFF *")
and vimagewidth_104.(LocalVariable).getFunction() = func
and vtif_49.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
