/**
 * @name krb5-b90b219ab8faa6bb0e7c2e7aa241aa7eeab0adac-krb5_pac_get_buffer
 * @id cpp/krb5/b90b219ab8faa6bb0e7c2e7aa241aa7eeab0adac/krb5-pac-get-buffer
 * @description krb5-b90b219ab8faa6bb0e7c2e7aa241aa7eeab0adac-lib/krb5/pac.c-krb5_pac_get_buffer CVE-2022-42898
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Function func) {
	exists(ValueFieldAccess target_2 |
		target_2.getTarget().getName()="offset"
		and target_2.getQualifier() instanceof ArrayExpr
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vdata_462, BlockStmt target_12, ExprStmt target_4) {
	exists(NotExpr target_3 |
		target_3.getOperand().(VariableAccess).getTarget()=vdata_462
		and target_3.getParent().(IfStmt).getThen()=target_12
		and target_3.getOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(Parameter vp_461, Parameter vdata_462, Variable vret_464, Variable vlen_468, Variable voffset_1_469, VariableAccess target_9, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_464
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("krb5_data_copy")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdata_462
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="data"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="data"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_461
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffset_1_469
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_468
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

predicate func_5(Parameter vp_461, Variable vi_465, ArrayExpr target_5) {
		target_5.getArrayBase().(PointerFieldAccess).getTarget().getName()="buffers"
		and target_5.getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pac"
		and target_5.getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_461
		and target_5.getArrayOffset().(VariableAccess).getTarget()=vi_465
}

predicate func_6(Variable vret_464, Parameter vcontext_461, VariableAccess target_13, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("krb5_set_error_message")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcontext_461
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vret_464
		and target_6.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="malloc: out of memory"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

predicate func_7(Variable vret_464, VariableAccess target_13, ReturnStmt target_7) {
		target_7.getExpr().(VariableAccess).getTarget()=vret_464
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
}

predicate func_8(Function func, ReturnStmt target_8) {
		target_8.getExpr().(Literal).getValue()="0"
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Parameter vdata_462, BlockStmt target_12, VariableAccess target_9) {
		target_9.getTarget()=vdata_462
		and target_9.getParent().(IfStmt).getThen()=target_12
}

predicate func_11(Function func, ValueFieldAccess target_11) {
		target_11.getTarget().getName()="offset_lo"
		and target_11.getQualifier() instanceof ArrayExpr
		and target_11.getEnclosingFunction() = func
}

predicate func_12(Variable vret_464, BlockStmt target_12) {
		target_12.getStmt(0) instanceof ExprStmt
		and target_12.getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vret_464
		and target_12.getStmt(1).(IfStmt).getThen() instanceof BlockStmt
}

predicate func_13(Variable vret_464, VariableAccess target_13) {
		target_13.getTarget()=vret_464
}

from Function func, Parameter vp_461, Parameter vdata_462, Variable vret_464, Variable vi_465, Variable vlen_468, Variable voffset_1_469, Parameter vcontext_461, ExprStmt target_4, ArrayExpr target_5, ExprStmt target_6, ReturnStmt target_7, ReturnStmt target_8, VariableAccess target_9, ValueFieldAccess target_11, BlockStmt target_12, VariableAccess target_13
where
not func_2(func)
and not func_3(vdata_462, target_12, target_4)
and func_4(vp_461, vdata_462, vret_464, vlen_468, voffset_1_469, target_9, target_4)
and func_5(vp_461, vi_465, target_5)
and func_6(vret_464, vcontext_461, target_13, target_6)
and func_7(vret_464, target_13, target_7)
and func_8(func, target_8)
and func_9(vdata_462, target_12, target_9)
and func_11(func, target_11)
and func_12(vret_464, target_12)
and func_13(vret_464, target_13)
and vp_461.getType().hasName("krb5_const_pac")
and vdata_462.getType().hasName("krb5_data *")
and vret_464.getType().hasName("krb5_error_code")
and vi_465.getType().hasName("uint32_t")
and vlen_468.getType().hasName("const size_t")
and voffset_1_469.getType().hasName("const size_t")
and vcontext_461.getType().hasName("krb5_context")
and vp_461.getParentScope+() = func
and vdata_462.getParentScope+() = func
and vret_464.getParentScope+() = func
and vi_465.getParentScope+() = func
and vlen_468.getParentScope+() = func
and voffset_1_469.getParentScope+() = func
and vcontext_461.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
