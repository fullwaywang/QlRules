/**
 * @name mysql-server-44e4da61d1d1341ecf2b74a99acbc357ca3357cf-Rsa_authentication_keys__read_key_file
 * @id cpp/mysql-server/44e4da61d1d1341ecf2b74a99acbc357ca3357cf/rsaauthenticationkeysreadkeyfile
 * @description mysql-server-44e4da61d1d1341ecf2b74a99acbc357ca3357cf-sql/auth/sql_authentication.cc-Rsa_authentication_keys__read_key_file mysql-#34274914
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vkey_file_1173, NotExpr target_1, ExprStmt target_2, ExprStmt target_3) {
exists(ExprStmt target_0 |
	exists(FunctionCall obj_0 | obj_0=target_0.getExpr() |
		obj_0.getTarget().hasName("fclose")
		and obj_0.getArgument(0).(VariableAccess).getTarget()=vkey_file_1173
	)
	and exists(BlockStmt obj_1 | obj_1=target_0.getParent() |
		exists(IfStmt obj_2 | obj_2=obj_1.getParent() |
			obj_2.getThen().(BlockStmt).getStmt(4)=target_0
			and obj_2.getCondition()=target_1
		)
	)
	and target_2.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
	and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
)
}

predicate func_1(Function func, NotExpr target_1) {
	target_1.getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("RSA **")
	and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vkey_file_1173, ExprStmt target_2) {
	exists(AssignExpr obj_0 | obj_0=target_2.getExpr() |
		exists(ConditionalExpr obj_1 | obj_1=obj_0.getRValue() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getThen() |
				obj_2.getTarget().hasName("PEM_read_RSAPrivateKey")
				and obj_2.getArgument(0).(VariableAccess).getTarget()=vkey_file_1173
				and obj_2.getArgument(1).(Literal).getValue()="0"
				and obj_2.getArgument(2).(Literal).getValue()="0"
				and obj_2.getArgument(3).(Literal).getValue()="0"
			)
			and exists(FunctionCall obj_3 | obj_3=obj_1.getElse() |
				obj_3.getTarget().hasName("PEM_read_RSA_PUBKEY")
				and obj_3.getArgument(0).(VariableAccess).getTarget()=vkey_file_1173
				and obj_3.getArgument(1).(Literal).getValue()="0"
				and obj_3.getArgument(2).(Literal).getValue()="0"
				and obj_3.getArgument(3).(Literal).getValue()="0"
			)
			and obj_1.getCondition().(VariableAccess).getTarget().getType().hasName("bool")
		)
		and obj_0.getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().getType().hasName("RSA **")
	)
}

predicate func_3(Variable vkey_file_1173, ExprStmt target_3) {
	exists(FunctionCall obj_0 | obj_0=target_3.getExpr() |
		obj_0.getTarget().hasName("fseek")
		and obj_0.getArgument(0).(VariableAccess).getTarget()=vkey_file_1173
		and obj_0.getArgument(1).(Literal).getValue()="0"
		and obj_0.getArgument(2).(Literal).getValue()="2"
	)
}

from Function func, Variable vkey_file_1173, NotExpr target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vkey_file_1173, target_1, target_2, target_3)
and func_1(func, target_1)
and func_2(vkey_file_1173, target_2)
and func_3(vkey_file_1173, target_3)
and vkey_file_1173.getType().hasName("FILE *")
and vkey_file_1173.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
