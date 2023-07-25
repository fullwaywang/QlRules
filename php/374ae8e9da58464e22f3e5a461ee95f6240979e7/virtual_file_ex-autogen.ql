/**
 * @name php-374ae8e9da58464e22f3e5a461ee95f6240979e7-virtual_file_ex
 * @id cpp/php/374ae8e9da58464e22f3e5a461ee95f6240979e7/virtual-file-ex
 * @description php-374ae8e9da58464e22f3e5a461ee95f6240979e7-Zend/zend_virtual_cwd.c-virtual_file_ex CVE-2016-6289
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpath_length_1181, BlockStmt target_4) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vpath_length_1181
		and target_0.getGreaterOperand() instanceof Literal
		and target_0.getParent().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vpath_length_1181
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4095"
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_4)
}

predicate func_1(Variable vpath_length_1181, VariableAccess target_1) {
		target_1.getTarget()=vpath_length_1181
}

predicate func_3(Variable vpath_length_1181, BlockStmt target_4, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vpath_length_1181
		and target_3.getAnOperand() instanceof Literal
		and target_3.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vpath_length_1181
		and target_3.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4095"
		and target_3.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_4
}

predicate func_4(BlockStmt target_4) {
		target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="22"
		and target_4.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="1"
}

from Function func, Variable vpath_length_1181, VariableAccess target_1, EqualityOperation target_3, BlockStmt target_4
where
not func_0(vpath_length_1181, target_4)
and func_1(vpath_length_1181, target_1)
and func_3(vpath_length_1181, target_4, target_3)
and func_4(target_4)
and vpath_length_1181.getType().hasName("int")
and vpath_length_1181.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
