/**
 * @name libtiff-eecb0712f4c3a5b449f70c57988260a667ddbdef-TIFFFetchStripThing
 * @id cpp/libtiff/eecb0712f4c3a5b449f70c57988260a667ddbdef/TIFFFetchStripThing
 * @description libtiff-eecb0712f4c3a5b449f70c57988260a667ddbdef-libtiff/tif_dirread.c-TIFFFetchStripThing CVE-2022-0561
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdir_5744, RelationalOperation target_2, FunctionCall target_3, MulExpr target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="tdir_count"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdir_5744
		and target_0.getThen() instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(9)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vdir_5744, Variable vdata_5748, Variable vresizeddata_5758, RelationalOperation target_2, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("_TIFFmemcpy")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vresizeddata_5758
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdata_5748
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="tdir_count"
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdir_5744
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="8"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Parameter vdir_5744, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(PointerFieldAccess).getTarget().getName()="tdir_count"
		and target_2.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdir_5744
		and target_2.getGreaterOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_3(Parameter vdir_5744, FunctionCall target_3) {
		target_3.getTarget().hasName("TIFFFieldWithTag")
		and target_3.getArgument(0).(VariableAccess).getTarget().getType().hasName("TIFF *")
		and target_3.getArgument(1).(PointerFieldAccess).getTarget().getName()="tdir_tag"
		and target_3.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdir_5744
}

predicate func_4(Parameter vdir_5744, MulExpr target_4) {
		target_4.getLeftOperand().(PointerFieldAccess).getTarget().getName()="tdir_count"
		and target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdir_5744
		and target_4.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_4.getRightOperand().(SizeofTypeOperator).getValue()="8"
}

from Function func, Parameter vdir_5744, Variable vdata_5748, Variable vresizeddata_5758, ExprStmt target_1, RelationalOperation target_2, FunctionCall target_3, MulExpr target_4
where
not func_0(vdir_5744, target_2, target_3, target_4)
and func_1(vdir_5744, vdata_5748, vresizeddata_5758, target_2, target_1)
and func_2(vdir_5744, target_2)
and func_3(vdir_5744, target_3)
and func_4(vdir_5744, target_4)
and vdir_5744.getType().hasName("TIFFDirEntry *")
and vdata_5748.getType().hasName("uint64_t *")
and vresizeddata_5758.getType().hasName("uint64_t *")
and vdir_5744.getFunction() = func
and vdata_5748.(LocalVariable).getFunction() = func
and vresizeddata_5758.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
