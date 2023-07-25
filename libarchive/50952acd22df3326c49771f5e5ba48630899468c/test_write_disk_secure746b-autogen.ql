/**
 * @name libarchive-50952acd22df3326c49771f5e5ba48630899468c-test_write_disk_secure746b
 * @id cpp/libarchive/50952acd22df3326c49771f5e5ba48630899468c/test-write-disk-secure746b
 * @description libarchive-50952acd22df3326c49771f5e5ba48630899468c-libarchive/test/test_write_disk_secure746.c-test_write_disk_secure746b CVE-2016-5418
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vae_88, Variable va_87, UnaryMinusExpr target_0) {
		target_0.getValue()="-25"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("assertion_equal_int")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("archive_write_header")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=va_87
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vae_88
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="archive_write_header(a, ae)"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6) instanceof Literal
}

predicate func_1(Variable va_87, UnaryMinusExpr target_1) {
		target_1.getValue()="-25"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("assertion_equal_int")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("archive_write_data")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=va_87
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(2) instanceof Literal
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="archive_write_data(a, \"modified\", 8)"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6) instanceof Literal
}

predicate func_2(Variable vae_88, ExprStmt target_10, FunctionCall target_11) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("archive_entry_set_mode")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vae_88
		and target_2.getArgument(1).(BitwiseOrExpr).getValue()="41471"
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getArgument(0).(VariableAccess).getLocation())
		and target_2.getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getArgument(1).(VariableAccess).getLocation()))
}

predicate func_5(Variable va_87, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("assertion_equal_int")
		and target_5.getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_5.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_5.getExpr().(FunctionCall).getArgument(2).(UnaryMinusExpr).getValue()="-30"
		and target_5.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_5.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("archive_write_data")
		and target_5.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=va_87
		and target_5.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_5.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(2) instanceof Literal
		and target_5.getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="archive_write_data(a, \"modified\", 8)"
		and target_5.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=va_87
		and (func.getEntryPoint().(BlockStmt).getStmt(21)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(21).getFollowingStmt()=target_5))
}

predicate func_7(Variable va_87, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("assertion_equal_int")
		and target_7.getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_7.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_7.getExpr().(FunctionCall).getArgument(2).(UnaryMinusExpr).getValue()="-30"
		and target_7.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_7.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("archive_write_close")
		and target_7.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=va_87
		and target_7.getExpr().(FunctionCall).getArgument(5) instanceof StringLiteral
		and target_7.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=va_87
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_7))
}

predicate func_8(Variable va_87, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("archive_write_free")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=va_87
		and (func.getEntryPoint().(BlockStmt).getStmt(25)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(25).getFollowingStmt()=target_8))
}

predicate func_9(Variable vae_88, Variable va_87, UnaryMinusExpr target_9) {
		target_9.getValue()="-25"
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("assertion_equal_int")
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("archive_write_header")
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=va_87
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vae_88
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="archive_write_header(a, ae)"
		and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6) instanceof Literal
}

predicate func_10(Variable vae_88, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("archive_entry_copy_symlink")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vae_88
		and target_10.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="../target"
}

predicate func_11(Variable vae_88, Variable va_87, FunctionCall target_11) {
		target_11.getTarget().hasName("archive_write_header")
		and target_11.getArgument(0).(VariableAccess).getTarget()=va_87
		and target_11.getArgument(1).(VariableAccess).getTarget()=vae_88
}

from Function func, Variable vae_88, Variable va_87, UnaryMinusExpr target_0, UnaryMinusExpr target_1, UnaryMinusExpr target_9, ExprStmt target_10, FunctionCall target_11
where
func_0(vae_88, va_87, target_0)
and func_1(va_87, target_1)
and not func_2(vae_88, target_10, target_11)
and not func_5(va_87, func)
and not func_7(va_87, func)
and not func_8(va_87, func)
and func_9(vae_88, va_87, target_9)
and func_10(vae_88, target_10)
and func_11(vae_88, va_87, target_11)
and vae_88.getType().hasName("archive_entry *")
and va_87.getType().hasName("archive *")
and vae_88.getParentScope+() = func
and va_87.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
