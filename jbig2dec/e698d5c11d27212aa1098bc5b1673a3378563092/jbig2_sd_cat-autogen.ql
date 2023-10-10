/**
 * @name jbig2dec-e698d5c11d27212aa1098bc5b1673a3378563092-jbig2_sd_cat
 * @id cpp/jbig2dec/e698d5c11d27212aa1098bc5b1673a3378563092/jbig2-sd-cat
 * @description jbig2dec-e698d5c11d27212aa1098bc5b1673a3378563092-jbig2_symbol_dict.c-jbig2_sd_cat CVE-2016-9601
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Initializer target_0) {
		target_0.getExpr().(Literal).getValue()="0"
		and target_0.getExpr().getEnclosingFunction() = func
}

predicate func_1(Variable vnew_201, BlockStmt target_9, VariableAccess target_1) {
		target_1.getTarget()=vnew_201
		and target_1.getParent().(NEExpr).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_9
}

predicate func_2(Variable vnew_201, VariableAccess target_2) {
		target_2.getTarget()=vnew_201
}

predicate func_3(Variable vnew_201, VariableAccess target_3) {
		target_3.getTarget()=vnew_201
}

predicate func_8(Variable vnew_201, VariableAccess target_8) {
		target_8.getTarget()=vnew_201
		and target_8.getParent().(AssignExpr).getLValue() = target_8
		and target_8.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("jbig2_sd_new")
}

predicate func_9(BlockStmt target_9) {
		target_9.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_9.getStmt(1).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_9.getStmt(1).(ForStmt).getStmt().(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_9.getStmt(1).(ForStmt).getStmt().(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="n_symbols"
		and target_9.getStmt(1).(ForStmt).getStmt().(ForStmt).getStmt().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="glyphs"
		and target_9.getStmt(1).(ForStmt).getStmt().(ForStmt).getStmt().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("jbig2_image_clone")
}

from Function func, Variable vnew_201, Initializer target_0, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, VariableAccess target_8, BlockStmt target_9
where
func_0(func, target_0)
and func_1(vnew_201, target_9, target_1)
and func_2(vnew_201, target_2)
and func_3(vnew_201, target_3)
and func_8(vnew_201, target_8)
and func_9(target_9)
and vnew_201.getType().hasName("Jbig2SymbolDict *")
and vnew_201.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
