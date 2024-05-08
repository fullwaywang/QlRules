/**
 * @name mysql-server-5d6efe2bb9ebb103f9fc1f4166624fb04dc61e46-MgmApiSession__report_event
 * @id cpp/mysql-server/5d6efe2bb9ebb103f9fc1f4166624fb04dc61e46/mgmapisessionreportevent
 * @description mysql-server-5d6efe2bb9ebb103f9fc1f4166624fb04dc61e46-storage/ndb/src/mgmsrv/Services.cpp-MgmApiSession__report_event mysql-#32957547
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(ExprStmt target_2, Function func) {
exists(ExprStmt target_0 |
	target_0.getExpr().(Literal).getValue()="0"
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
	and target_0.getLocation().isBefore(target_2.getLocation())
)
}

predicate func_1(Variable vlength_1841, ForStmt target_3, AddressOfExpr target_4, RelationalOperation target_5, Function func) {
exists(IfStmt target_1 |
	exists(RelationalOperation obj_0 | obj_0=target_1.getCondition() |
		obj_0.getGreaterOperand().(VariableAccess).getTarget()=vlength_1841
		and obj_0.getLesserOperand().(VariableAccess).getType().hasName("unsigned int")
	)
	and exists(ExprStmt obj_1 | obj_1=target_1.getThen() |
		exists(AssignExpr obj_2 | obj_2=obj_1.getExpr() |
			obj_2.getLValue().(VariableAccess).getTarget()=vlength_1841
			and obj_2.getRValue().(VariableAccess).getType().hasName("unsigned int")
		)
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
	and target_1.getLocation().isBefore(target_3.getLocation())
	and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
	and target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getGreaterOperand().(VariableAccess).getLocation())
)
}

predicate func_2(Function func, ExprStmt target_2) {
	exists(FunctionCall obj_0 | obj_0=target_2.getExpr() |
		obj_0.getTarget().hasName("get")
		and obj_0.getQualifier().(VariableAccess).getTarget().getType().hasName("const Properties &")
		and obj_0.getArgument(0).(StringLiteral).getValue()="data"
		and obj_0.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("const char *")
	)
	and target_2.getEnclosingFunction() = func
}

predicate func_3(Variable vlength_1841, ForStmt target_3) {
	exists(RelationalOperation obj_0 | obj_0=target_3.getCondition() |
		obj_0.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and obj_0.getGreaterOperand().(VariableAccess).getTarget()=vlength_1841
	)
	and exists(BlockStmt obj_1 | obj_1=target_3.getStmt() |
		exists(ExprStmt obj_2 | obj_2=obj_1.getStmt(0) |
			exists(FunctionCall obj_3 | obj_3=obj_2.getExpr() |
				exists(FunctionCall obj_4 | obj_4=obj_3.getArgument(0) |
					exists(OverloadedArrayExpr obj_5 | obj_5=obj_4.getQualifier() |
						obj_5.getQualifier().(VariableAccess).getTarget().getType().hasName("Vector<BaseString>")
						and obj_5.getAChild().(VariableAccess).getTarget().getType().hasName("int")
					)
					and obj_4.getTarget().hasName("c_str")
				)
				and exists(PointerArithmeticOperation obj_6 | obj_6=obj_3.getArgument(2) |
					obj_6.getLeftOperand().(VariableAccess).getTarget().getType().hasName("Uint32[25]")
					and obj_6.getRightOperand().(VariableAccess).getTarget().getType().hasName("int")
				)
				and obj_3.getTarget().hasName("sscanf")
				and obj_3.getArgument(1).(StringLiteral).getValue()="%u"
			)
		)
	)
	and target_3.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_4(Variable vlength_1841, AddressOfExpr target_4) {
	target_4.getOperand().(VariableAccess).getTarget()=vlength_1841
}

predicate func_5(Variable vlength_1841, RelationalOperation target_5) {
	 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
	and target_5.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
	and target_5.getGreaterOperand().(VariableAccess).getTarget()=vlength_1841
}

from Function func, Variable vlength_1841, ExprStmt target_2, ForStmt target_3, AddressOfExpr target_4, RelationalOperation target_5
where
not func_0(target_2, func)
and not func_1(vlength_1841, target_3, target_4, target_5, func)
and func_2(func, target_2)
and func_3(vlength_1841, target_3)
and func_4(vlength_1841, target_4)
and func_5(vlength_1841, target_5)
and vlength_1841.getType().hasName("Uint32")
and vlength_1841.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
