/**
 * @name lldpd-73d42680fce8598324364dbb31b9bc3b8320adf7-sonmp_decode
 * @id cpp/lldpd/73d42680fce8598324364dbb31b9bc3b8320adf7/sonmp-decode
 * @description lldpd-73d42680fce8598324364dbb31b9bc3b8320adf7-src/daemon/protocols/sonmp.c-sonmp_decode CVE-2021-43612
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_4, Function func, AddExpr target_0) {
		target_0.getValue()="22"
		and target_0.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_4
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func) {
	exists(AddExpr target_1 |
		target_1.getValue()="31"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func, MulExpr target_2) {
		target_2.getValue()="12"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, SizeofTypeOperator target_3) {
		target_3.getType() instanceof LongType
		and target_3.getValue()="2"
		and target_3.getEnclosingFunction() = func
}

predicate func_4(BlockStmt target_4) {
		target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("log_warnx")
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="sonmp"
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="too short SONMP frame received on %s"
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="h_ifname"
		and target_4.getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_4.getStmt(1).(GotoStmt).getName() ="malformed"
}

from Function func, AddExpr target_0, MulExpr target_2, SizeofTypeOperator target_3, BlockStmt target_4
where
func_0(target_4, func, target_0)
and not func_1(func)
and func_2(func, target_2)
and func_3(func, target_3)
and func_4(target_4)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
