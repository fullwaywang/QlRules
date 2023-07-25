/**
 * @name libtiff-c7153361a4041260719b340f73f2f76b0969235c-t2p_readwrite_pdf_image_tile
 * @id cpp/libtiff/c7153361a4041260719b340f73f2f76b0969235c/t2p-readwrite-pdf-image-tile
 * @description libtiff-c7153361a4041260719b340f73f2f76b0969235c-tools/tiff2pdf.c-t2p_readwrite_pdf_image_tile CVE-2016-10094
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcount_2886, BlockStmt target_4, AddressOfExpr target_5, SubExpr target_6) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vcount_2886
		and target_0.getLesserOperand() instanceof Literal
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_5.getOperand().(VariableAccess).getLocation().isBefore(target_0.getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_6.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcount_2886, BlockStmt target_4, VariableAccess target_1) {
		target_1.getTarget()=vcount_2886
		and target_1.getParent().(GEExpr).getLesserOperand().(Literal).getValue()="4"
		and target_1.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Variable vcount_2886, BlockStmt target_4, RelationalOperation target_3) {
		 (target_3 instanceof GEExpr or target_3 instanceof LEExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vcount_2886
		and target_3.getLesserOperand() instanceof Literal
		and target_3.getParent().(IfStmt).getThen()=target_4
}

predicate func_4(Variable vcount_2886, BlockStmt target_4) {
		target_4.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFmemcpy")
		and target_4.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_4.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_4.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vcount_2886
		and target_4.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(Literal).getValue()="2"
}

predicate func_5(Variable vcount_2886, AddressOfExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vcount_2886
}

predicate func_6(Variable vcount_2886, SubExpr target_6) {
		target_6.getLeftOperand().(VariableAccess).getTarget()=vcount_2886
		and target_6.getRightOperand().(Literal).getValue()="2"
}

from Function func, Variable vcount_2886, VariableAccess target_1, RelationalOperation target_3, BlockStmt target_4, AddressOfExpr target_5, SubExpr target_6
where
not func_0(vcount_2886, target_4, target_5, target_6)
and func_1(vcount_2886, target_4, target_1)
and func_3(vcount_2886, target_4, target_3)
and func_4(vcount_2886, target_4)
and func_5(vcount_2886, target_5)
and func_6(vcount_2886, target_6)
and vcount_2886.getType().hasName("uint32")
and vcount_2886.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
