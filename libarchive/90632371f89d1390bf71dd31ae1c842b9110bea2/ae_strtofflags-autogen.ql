/**
 * @name libarchive-90632371f89d1390bf71dd31ae1c842b9110bea2-ae_strtofflags
 * @id cpp/libarchive/90632371f89d1390bf71dd31ae1c842b9110bea2/ae-strtofflags
 * @description libarchive-90632371f89d1390bf71dd31ae1c842b9110bea2-libarchive/archive_entry.c-ae_strtofflags CVE-2015-8921
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vstart_1739, Variable vflag_1740, FunctionCall target_0) {
		target_0.getTarget().hasName("strcmp")
		and not target_0.getTarget().hasName("memcmp")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vstart_1739
		and target_0.getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vflag_1740
}

predicate func_1(Variable vstart_1739, Variable vflag_1740, FunctionCall target_1) {
		target_1.getTarget().hasName("strcmp")
		and not target_1.getTarget().hasName("memcmp")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vstart_1739
		and target_1.getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="name"
		and target_1.getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vflag_1740
		and target_1.getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
}

predicate func_2(Variable vstart_1739, Variable vflag_1740, BlockStmt target_10, ExprStmt target_12) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstart_1739
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vflag_1740
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("size_t")
		and target_2.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_2.getParent().(IfStmt).getThen()=target_10
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignOrExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(Variable vstart_1739, Variable vflag_1740, BlockStmt target_13, ExprStmt target_15, ExprStmt target_16, ExprStmt target_17) {
	exists(LogicalAndExpr target_6 |
		target_6.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(VariableAccess).getType().hasName("size_t")
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstart_1739
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="name"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vflag_1740
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("size_t")
		and target_6.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_6.getParent().(IfStmt).getThen()=target_13
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_16.getExpr().(AssignOrExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getExpr().(AssignOrExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_10(Variable vflag_1740, BlockStmt target_10) {
		target_10.getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(PointerFieldAccess).getTarget().getName()="set"
		and target_10.getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vflag_1740
		and target_10.getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(PointerFieldAccess).getTarget().getName()="clear"
		and target_10.getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vflag_1740
		and target_10.getStmt(2).(BreakStmt).toString() = "break;"
}

predicate func_12(Variable vflag_1740, ExprStmt target_12) {
		target_12.getExpr().(AssignOrExpr).getRValue().(PointerFieldAccess).getTarget().getName()="set"
		and target_12.getExpr().(AssignOrExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vflag_1740
}

predicate func_13(Variable vflag_1740, BlockStmt target_13) {
		target_13.getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(PointerFieldAccess).getTarget().getName()="set"
		and target_13.getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vflag_1740
		and target_13.getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(PointerFieldAccess).getTarget().getName()="clear"
		and target_13.getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vflag_1740
		and target_13.getStmt(2).(BreakStmt).toString() = "break;"
}

predicate func_15(Variable vstart_1739, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vstart_1739
}

predicate func_16(Variable vflag_1740, ExprStmt target_16) {
		target_16.getExpr().(AssignOrExpr).getRValue().(PointerFieldAccess).getTarget().getName()="clear"
		and target_16.getExpr().(AssignOrExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vflag_1740
}

predicate func_17(Variable vflag_1740, ExprStmt target_17) {
		target_17.getExpr().(AssignOrExpr).getRValue().(PointerFieldAccess).getTarget().getName()="set"
		and target_17.getExpr().(AssignOrExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vflag_1740
}

from Function func, Variable vstart_1739, Variable vflag_1740, FunctionCall target_0, FunctionCall target_1, BlockStmt target_10, ExprStmt target_12, BlockStmt target_13, ExprStmt target_15, ExprStmt target_16, ExprStmt target_17
where
func_0(vstart_1739, vflag_1740, target_0)
and func_1(vstart_1739, vflag_1740, target_1)
and not func_2(vstart_1739, vflag_1740, target_10, target_12)
and not func_6(vstart_1739, vflag_1740, target_13, target_15, target_16, target_17)
and func_10(vflag_1740, target_10)
and func_12(vflag_1740, target_12)
and func_13(vflag_1740, target_13)
and func_15(vstart_1739, target_15)
and func_16(vflag_1740, target_16)
and func_17(vflag_1740, target_17)
and vstart_1739.getType().hasName("const char *")
and vflag_1740.getType().hasName("flag *")
and vstart_1739.getParentScope+() = func
and vflag_1740.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
